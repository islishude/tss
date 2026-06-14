package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	keygenPlanDigestLabel  = "frost-ed25519-keygen-plan-v1"
	refreshPlanDigestLabel = "frost-ed25519-refresh-plan-v1"
	resharePlanDigestLabel = "frost-ed25519-reshare-plan-v1"
	signPlanDigestLabel    = "frost-ed25519-sign-plan-v1"
)

var errPlanHashMismatch = errors.New("lifecycle plan hash mismatch")

type keygenPlanState struct {
	sessionID tss.SessionID
	threshold int
	parties   []tss.PartyID
	enableHD  bool
}

// KeygenPlan is the shared FROST keygen intent.
type KeygenPlan struct {
	state *keygenPlanState
}

// NewKeygenPlan constructs a FROST keygen plan.
func NewKeygenPlan(sessionID tss.SessionID, parties []tss.PartyID, threshold int, enableHD bool) (*KeygenPlan, error) {
	parties, err := validatePlanParties(parties, threshold, DefaultLimits())
	if err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	if !sessionID.Valid() {
		return nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	return &KeygenPlan{state: &keygenPlanState{
		sessionID: sessionID,
		threshold: threshold,
		parties:   parties,
		enableHD:  enableHD,
	}}, nil
}

// SessionID returns the keygen session ID.
func (p *KeygenPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Threshold returns the signing threshold.
func (p *KeygenPlan) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.threshold
}

// Parties returns a copy of the canonical party set.
func (p *KeygenPlan) Parties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.parties)
}

// EnableHD reports whether keygen will aggregate an HD chain code.
func (p *KeygenPlan) EnableHD() bool {
	return p != nil && p.state != nil && p.state.enableHD
}

// Digest returns the canonical keygen plan digest.
func (p *KeygenPlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil keygen plan")
	}
	t := transcript.New(keygenPlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendUint32("threshold", uint32(p.state.threshold))
	t.AppendUint32List("parties", transcript.Uint32s(p.state.parties))
	t.AppendBool("enable_hd", p.state.enableHD)
	return t.Sum(), nil
}

func (p *KeygenPlan) thresholdConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if p == nil || p.state == nil {
		return tss.ThresholdConfig{}, errors.New("nil keygen plan")
	}
	if !tss.ContainsParty(p.state.parties, local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in keygen plan")
	}
	return tss.ThresholdConfig{
		Threshold:    p.state.threshold,
		Parties:      slices.Clone(p.state.parties),
		Self:         local.Self,
		SessionID:    p.state.sessionID,
		Rand:         local.Rand,
		Context:      local.Context,
		RoundTimeout: local.RoundTimeout,
		Log:          local.Log,
	}, nil
}

type refreshPlanState struct {
	sessionID tss.SessionID
	threshold int
	parties   []tss.PartyID
	publicKey []byte
	chainCode []byte
}

// RefreshPlan is the shared FROST same-party refresh intent.
type RefreshPlan struct {
	state *refreshPlanState
}

// NewRefreshPlan constructs a refresh plan from an existing key share.
func NewRefreshPlan(oldKey *KeyShare, sessionID tss.SessionID) (*RefreshPlan, error) {
	if oldKey == nil || oldKey.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	if !sessionID.Valid() {
		return nil, invalidPlanConfig(oldKey.state.party, tss.ErrInvalidSessionID)
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	return &RefreshPlan{state: &refreshPlanState{
		sessionID: sessionID,
		threshold: oldKey.state.threshold,
		parties:   slices.Clone(oldKey.state.parties),
		publicKey: slices.Clone(oldKey.state.publicKey),
		chainCode: slices.Clone(oldKey.state.chainCode),
	}}, nil
}

// SessionID returns the refresh session ID.
func (p *RefreshPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Threshold returns the fixed refresh threshold.
func (p *RefreshPlan) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.threshold
}

// Parties returns a copy of the fixed refresh participant set.
func (p *RefreshPlan) Parties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.parties)
}

// PublicKeyBytes returns a copy of the group public key bound by the plan.
func (p *RefreshPlan) PublicKeyBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.publicKey)
}

// ChainCodeBytes returns a copy of the HD chain code bound by the plan.
func (p *RefreshPlan) ChainCodeBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.chainCode)
}

// Digest returns the canonical refresh plan digest.
func (p *RefreshPlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil refresh plan")
	}
	t := transcript.New(refreshPlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendUint32("threshold", uint32(p.state.threshold))
	t.AppendUint32List("parties", transcript.Uint32s(p.state.parties))
	t.AppendBytes("public_key", p.state.publicKey)
	t.AppendBytes("chain_code", p.state.chainCode)
	return t.Sum(), nil
}

func (p *RefreshPlan) thresholdConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if p == nil || p.state == nil {
		return tss.ThresholdConfig{}, errors.New("nil refresh plan")
	}
	if !tss.ContainsParty(p.state.parties, local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in refresh plan")
	}
	return tss.ThresholdConfig{
		Threshold:    p.state.threshold,
		Parties:      slices.Clone(p.state.parties),
		Self:         local.Self,
		SessionID:    p.state.sessionID,
		Rand:         local.Rand,
		Context:      local.Context,
		RoundTimeout: local.RoundTimeout,
		Log:          local.Log,
	}, nil
}

type resharePlanState struct {
	sessionID    tss.SessionID
	oldPublicKey []byte
	oldChainCode []byte
	oldParties   []tss.PartyID
	newParties   []tss.PartyID
	newThreshold int
}

// ResharePlan is the shared FROST reshare intent.
type ResharePlan struct {
	state *resharePlanState
}

// NewResharePlan constructs a FROST reshare plan from an old key share.
func NewResharePlan(oldKey *KeyShare, sessionID tss.SessionID, newParties []tss.PartyID, newThreshold int) (*ResharePlan, error) {
	if oldKey == nil || oldKey.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	return NewResharePlanFromPublic(oldKey.state.publicKey, oldKey.state.chainCode, oldKey.state.parties, sessionID, newParties, newThreshold)
}

// NewResharePlanFromPublic constructs a FROST reshare plan for new-only
// recipients that do not hold an old key share.
func NewResharePlanFromPublic(oldPublicKey, oldChainCode []byte, oldParties []tss.PartyID, sessionID tss.SessionID, newParties []tss.PartyID, newThreshold int) (*ResharePlan, error) {
	if !sessionID.Valid() {
		return nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	if _, err := edcurve.PointFromBytes(oldPublicKey); err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old public key: %w", err))
	}
	if len(oldChainCode) != 0 && len(oldChainCode) != 32 {
		return nil, invalidPlanConfig(0, errors.New("old chain code must be empty or 32 bytes"))
	}
	limits := DefaultLimits()
	oldParties, err := validatePlanPartySet(oldParties, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old participant set: %w", err))
	}
	newParties, err = validatePlanParties(newParties, newThreshold, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	return &ResharePlan{state: &resharePlanState{
		sessionID:    sessionID,
		oldPublicKey: slices.Clone(oldPublicKey),
		oldChainCode: slices.Clone(oldChainCode),
		oldParties:   oldParties,
		newParties:   newParties,
		newThreshold: newThreshold,
	}}, nil
}

// SessionID returns the reshare session ID.
func (p *ResharePlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// OldPublicKeyBytes returns a copy of the old group public key.
func (p *ResharePlan) OldPublicKeyBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.oldPublicKey)
}

// OldChainCodeBytes returns a copy of the old HD chain code.
func (p *ResharePlan) OldChainCodeBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.oldChainCode)
}

// OldParties returns a copy of the old dealer set.
func (p *ResharePlan) OldParties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.oldParties)
}

// NewParties returns a copy of the new recipient set.
func (p *ResharePlan) NewParties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.newParties)
}

// NewThreshold returns the target signing threshold.
func (p *ResharePlan) NewThreshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.newThreshold
}

// Digest returns the canonical reshare plan digest.
func (p *ResharePlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil reshare plan")
	}
	t := transcript.New(resharePlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendBytes("old_public_key", p.state.oldPublicKey)
	t.AppendBytes("old_chain_code", p.state.oldChainCode)
	t.AppendUint32List("old_parties", transcript.Uint32s(p.state.oldParties))
	t.AppendUint32List("new_parties", transcript.Uint32s(p.state.newParties))
	t.AppendUint32("new_threshold", uint32(p.state.newThreshold))
	return t.Sum(), nil
}

// IsRecipient reports whether party is in the new participant set.
func (p *ResharePlan) IsRecipient(party tss.PartyID) bool {
	return p != nil && p.state != nil && tss.ContainsParty(p.state.newParties, party)
}

// IsDealer reports whether party is in the old participant set.
func (p *ResharePlan) IsDealer(party tss.PartyID) bool {
	return p != nil && p.state != nil && tss.ContainsParty(p.state.oldParties, party)
}

func (p *ResharePlan) dealerConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if p == nil || p.state == nil {
		return tss.ThresholdConfig{}, errors.New("nil reshare plan")
	}
	if !p.IsDealer(local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in old dealer set")
	}
	return tss.ThresholdConfig{
		Threshold:    len(p.state.oldParties),
		Parties:      slices.Clone(p.state.oldParties),
		Self:         local.Self,
		SessionID:    p.state.sessionID,
		Rand:         local.Rand,
		Context:      local.Context,
		RoundTimeout: local.RoundTimeout,
		Log:          local.Log,
	}, nil
}

func (p *ResharePlan) receiverConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if p == nil || p.state == nil {
		return tss.ThresholdConfig{}, errors.New("nil reshare plan")
	}
	if !p.IsRecipient(local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in new receiver set")
	}
	return tss.ThresholdConfig{
		Threshold:    p.state.newThreshold,
		Parties:      slices.Clone(p.state.newParties),
		Self:         local.Self,
		SessionID:    p.state.sessionID,
		Rand:         local.Rand,
		Context:      local.Context,
		RoundTimeout: local.RoundTimeout,
		Log:          local.Log,
	}, nil
}

type signPlanState struct {
	sessionID     tss.SessionID
	threshold     int
	parties       []tss.PartyID
	publicKey     []byte
	chainCode     []byte
	keygenHash    []byte
	signers       []tss.PartyID
	message       []byte
	additiveShift []byte
}

// SignPlan is the shared FROST signing intent.
type SignPlan struct {
	state *signPlanState
}

// NewSignPlan constructs a signing plan for the supplied key and signer set.
func NewSignPlan(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, message []byte, additiveShift []byte) (*SignPlan, error) {
	if key == nil || key.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil key share"))
	}
	if !sessionID.Valid() {
		return nil, invalidPlanConfig(key.state.party, tss.ErrInvalidSessionID)
	}
	if err := key.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	signers = tss.SortParties(signers)
	if err := validateSignerSet(key, signers, DefaultLimits()); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	if len(additiveShift) > 0 {
		if _, err := edcurve.ScalarFromCanonical(additiveShift); err != nil {
			return nil, invalidPlanConfig(key.state.party, fmt.Errorf("invalid additive shift: %w", err))
		}
	}
	if len(message) > DefaultLimits().Payload.MaxMessageBytes {
		return nil, invalidPlanConfig(key.state.party, fmt.Errorf("message too large: %d > %d", len(message), DefaultLimits().Payload.MaxMessageBytes))
	}
	return &SignPlan{state: &signPlanState{
		sessionID:     sessionID,
		threshold:     key.state.threshold,
		parties:       slices.Clone(key.state.parties),
		publicKey:     slices.Clone(key.state.publicKey),
		chainCode:     slices.Clone(key.state.chainCode),
		keygenHash:    slices.Clone(key.state.keygenTranscriptHash),
		signers:       signers,
		message:       slices.Clone(message),
		additiveShift: slices.Clone(additiveShift),
	}}, nil
}

// SessionID returns the signing session ID.
func (p *SignPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Signers returns a copy of the canonical signer set.
func (p *SignPlan) Signers() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.signers)
}

// Message returns a copy of the bound signing message.
func (p *SignPlan) Message() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.message)
}

// AdditiveShift returns a copy of the optional non-hardened HD additive shift.
func (p *SignPlan) AdditiveShift() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.additiveShift)
}

// Digest returns the canonical sign plan digest.
func (p *SignPlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil sign plan")
	}
	t := transcript.New(signPlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendUint32("threshold", uint32(p.state.threshold))
	t.AppendUint32List("parties", transcript.Uint32s(p.state.parties))
	t.AppendBytes("public_key", p.state.publicKey)
	t.AppendBytes("chain_code", p.state.chainCode)
	t.AppendBytes("keygen_transcript_hash", p.state.keygenHash)
	t.AppendUint32List("signers", transcript.Uint32s(p.state.signers))
	t.AppendBytes("message", p.state.message)
	t.AppendBytes("additive_shift", p.state.additiveShift)
	return t.Sum(), nil
}

func (p *SignPlan) validateKey(key *KeyShare, local tss.LocalConfig) error {
	if p == nil || p.state == nil {
		return errors.New("nil sign plan")
	}
	if key == nil || key.state == nil {
		return errors.New("nil key share")
	}
	if local.Self != key.state.party {
		return errors.New("local self must match key share party")
	}
	if !tss.ContainsParty(p.state.signers, local.Self) {
		return errors.New("local party is not in signer set")
	}
	if p.state.threshold != key.state.threshold ||
		!slices.Equal(p.state.parties, key.state.parties) ||
		!bytes.Equal(p.state.publicKey, key.state.publicKey) ||
		!bytes.Equal(p.state.chainCode, key.state.chainCode) ||
		!bytes.Equal(p.state.keygenHash, key.state.keygenTranscriptHash) {
		return errors.New("sign plan does not match key share")
	}
	return nil
}

func validatePlanParties(parties []tss.PartyID, threshold int, limits Limits) ([]tss.PartyID, error) {
	parties = tss.SortParties(parties)
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
	}
	if len(parties) == 0 {
		return nil, errors.New("parties must not be empty")
	}
	if len(parties) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("too many parties: %d > %d", len(parties), limits.Threshold.MaxParties)
	}
	if threshold > len(parties) {
		return nil, errors.New("threshold exceeds party count")
	}
	if threshold > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", threshold, limits.Threshold.MaxThreshold)
	}
	if err := limits.Threshold.ValidateThreshold(threshold, len(parties)); err != nil {
		return nil, err
	}
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return nil, err
	}
	return parties, nil
}

func validatePlanPartySet(parties []tss.PartyID, limits Limits) ([]tss.PartyID, error) {
	parties = tss.SortParties(parties)
	if len(parties) == 0 {
		return nil, errors.New("parties must not be empty")
	}
	if len(parties) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("too many parties: %d > %d", len(parties), limits.Threshold.MaxParties)
	}
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return nil, err
	}
	return parties, nil
}

func requirePlanHash(label string, got, want []byte) error {
	if len(got) != sha256.Size {
		return fmt.Errorf("%s plan hash must be %d bytes", label, sha256.Size)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s: %w", label, errPlanHashMismatch)
	}
	return nil
}

func invalidPlanConfig(party tss.PartyID, err error) error {
	if err == nil {
		return nil
	}
	var protocolErr *tss.ProtocolError
	if errors.As(err, &protocolErr) && protocolErr.Code == tss.ErrCodeInvalidConfig {
		return err
	}
	return tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, party, err)
}
