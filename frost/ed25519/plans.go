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

// KeygenPlanOption configures FROST keygen plan construction.
//
// SessionID, Parties, and Threshold are shared intent included in the plan
// digest. Limits is a local fail-closed resource policy and is intentionally
// excluded from the digest.
type KeygenPlanOption struct {
	SessionID tss.SessionID
	Parties   []tss.PartyID
	Threshold int
	Limits    *Limits
}

// KeygenPlan is the shared FROST keygen intent.
type KeygenPlan struct {
	sessionID tss.SessionID
	threshold int
	parties   []tss.PartyID
	limits    Limits
}

// NewKeygenPlan constructs a FROST keygen plan.
func NewKeygenPlan(option KeygenPlanOption) (*KeygenPlan, error) {
	limits := limitsOrDefault(option.Limits)
	parties, err := validatePlanParties(option.Parties, option.Threshold, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	return &KeygenPlan{
		sessionID: option.SessionID,
		threshold: option.Threshold,
		parties:   parties,
		limits:    limits,
	}, nil
}

// SessionID returns the keygen session ID.
func (p *KeygenPlan) SessionID() tss.SessionID {
	if p == nil {
		return tss.SessionID{}
	}
	return p.sessionID
}

// Threshold returns the signing threshold.
func (p *KeygenPlan) Threshold() int {
	if p == nil {
		return 0
	}
	return p.threshold
}

// Parties returns a copy of the canonical party set.
func (p *KeygenPlan) Parties() []tss.PartyID {
	if p == nil {
		return nil
	}
	return slices.Clone(p.parties)
}

// Digest returns the canonical keygen plan digest.
func (p *KeygenPlan) Digest() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	t := transcript.New(keygenPlanDigestLabel)
	t.AppendBytes("session_id", p.sessionID[:])
	t.AppendUint32("threshold", uint32(p.threshold))
	t.AppendUint32List("parties", p.parties)
	return t.Sum(), nil
}

func (p *KeygenPlan) validate() error {
	if p == nil {
		return errors.New("nil keygen plan")
	}
	if !p.sessionID.Valid() {
		return tss.ErrInvalidSessionID
	}
	if _, err := validatePlanParties(p.parties, p.threshold, p.limits); err != nil {
		return err
	}
	return nil
}

func (p *KeygenPlan) thresholdConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if err := p.validate(); err != nil {
		return tss.ThresholdConfig{}, err
	}
	if !tss.ContainsParty(p.parties, local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in keygen plan")
	}
	return tss.ThresholdConfig{
		Threshold:    p.threshold,
		Parties:      slices.Clone(p.parties),
		Self:         local.Self,
		SessionID:    p.sessionID,
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
	state  *refreshPlanState
	limits Limits
}

// RefreshPlanOption configures FROST refresh plan construction.
type RefreshPlanOption struct {
	OldKey    *KeyShare
	SessionID tss.SessionID
	Limits    *Limits
}

// NewRefreshPlan constructs a refresh plan from an existing key share.
func NewRefreshPlan(option RefreshPlanOption) (*RefreshPlan, error) {
	oldKey := option.OldKey
	limits := limitsOrDefault(option.Limits)
	if oldKey == nil || oldKey.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(oldKey.state.party, tss.ErrInvalidSessionID)
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	if _, err := validatePlanParties(oldKey.state.parties, oldKey.state.threshold, limits); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	return &RefreshPlan{state: &refreshPlanState{
		sessionID: option.SessionID,
		threshold: oldKey.state.threshold,
		parties:   slices.Clone(oldKey.state.parties),
		publicKey: slices.Clone(oldKey.state.publicKey),
		chainCode: slices.Clone(oldKey.state.chainCode),
	}, limits: limits}, nil
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
	t.AppendUint32List("parties", p.state.parties)
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
	state  *resharePlanState
	limits Limits
}

// ResharePlanOption configures FROST reshare plan construction from a key share.
type ResharePlanOption struct {
	OldKey       *KeyShare
	SessionID    tss.SessionID
	NewParties   []tss.PartyID
	NewThreshold int
	Limits       *Limits
}

// PublicResharePlanOption configures a public-only FROST reshare plan.
type PublicResharePlanOption struct {
	OldPublicKey []byte
	OldChainCode []byte
	OldParties   []tss.PartyID
	SessionID    tss.SessionID
	NewParties   []tss.PartyID
	NewThreshold int
	Limits       *Limits
}

// NewResharePlan constructs a FROST reshare plan from an old key share.
func NewResharePlan(option ResharePlanOption) (*ResharePlan, error) {
	oldKey := option.OldKey
	if oldKey == nil || oldKey.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	return NewPublicResharePlan(PublicResharePlanOption{
		OldPublicKey: oldKey.state.publicKey,
		OldChainCode: oldKey.state.chainCode,
		OldParties:   oldKey.state.parties,
		SessionID:    option.SessionID,
		NewParties:   option.NewParties,
		NewThreshold: option.NewThreshold,
		Limits:       option.Limits,
	})
}

// NewPublicResharePlan constructs a FROST reshare plan for new-only recipients
// that do not hold an old key share.
func NewPublicResharePlan(option PublicResharePlanOption) (*ResharePlan, error) {
	limits := limitsOrDefault(option.Limits)
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	if _, err := edcurve.PointFromBytes(option.OldPublicKey); err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old public key: %w", err))
	}
	if len(option.OldChainCode) != 32 {
		return nil, invalidPlanConfig(0, errors.New("old chain code must be 32 bytes"))
	}
	oldParties, err := validatePlanPartySet(option.OldParties, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old participant set: %w", err))
	}
	newParties, err := validatePlanParties(option.NewParties, option.NewThreshold, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	return &ResharePlan{state: &resharePlanState{
		sessionID:    option.SessionID,
		oldPublicKey: slices.Clone(option.OldPublicKey),
		oldChainCode: slices.Clone(option.OldChainCode),
		oldParties:   oldParties,
		newParties:   newParties,
		newThreshold: option.NewThreshold,
	}, limits: limits}, nil
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
	t.AppendUint32List("old_parties", p.state.oldParties)
	t.AppendUint32List("new_parties", p.state.newParties)
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
	sessionID       tss.SessionID
	threshold       int
	parties         []tss.PartyID
	publicKey       []byte
	chainCode       []byte
	keygenHash      []byte
	signers         []tss.PartyID
	context         tss.SigningContext
	contextHash     []byte
	derivation      *tss.DerivationResult
	verificationKey []byte
	message         []byte
}

// SignPlan is the shared FROST signing intent.
type SignPlan struct {
	state  *signPlanState
	limits Limits
}

// SignPlanOption configures FROST signing plan construction.
type SignPlanOption struct {
	Key       *KeyShare
	SessionID tss.SessionID
	Signers   []tss.PartyID
	Context   tss.SigningContext
	Message   []byte
	Limits    *Limits
}

// NewSignPlan constructs a signing plan for the supplied key and signer set.
func NewSignPlan(option SignPlanOption) (*SignPlan, error) {
	key := option.Key
	limits := limitsOrDefault(option.Limits)
	if key == nil || key.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil key share"))
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(key.state.party, tss.ErrInvalidSessionID)
	}
	if err := key.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	signers := tss.SortParties(option.Signers)
	if err := validateSignerSet(key, signers, limits); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	context, contextHash, derivation, err := prepareSignContext(key, option.Context)
	if err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	if limits.Payload.MaxMessageBytes <= 0 {
		return nil, invalidPlanConfig(key.state.party, errors.New("max message bytes must be positive"))
	}
	if len(option.Message) > limits.Payload.MaxMessageBytes {
		return nil, invalidPlanConfig(key.state.party, fmt.Errorf("message too large: %d > %d", len(option.Message), limits.Payload.MaxMessageBytes))
	}
	return &SignPlan{state: &signPlanState{
		sessionID:       option.SessionID,
		threshold:       key.state.threshold,
		parties:         slices.Clone(key.state.parties),
		publicKey:       slices.Clone(key.state.publicKey),
		chainCode:       slices.Clone(key.state.chainCode),
		keygenHash:      slices.Clone(key.state.keygenTranscriptHash),
		signers:         signers,
		context:         context, // already cloned in prepareSignContext
		contextHash:     slices.Clone(contextHash),
		derivation:      derivation.Clone(),
		verificationKey: slices.Clone(derivation.ChildPublicKey),
		message:         slices.Clone(option.Message),
	}, limits: limits}, nil
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

// Context returns a copy of the signing context bound by the plan.
func (p *SignPlan) Context() tss.SigningContext {
	if p == nil || p.state == nil {
		return tss.SigningContext{}
	}
	return p.state.context.Clone()
}

// Derivation returns a copy of the derivation result bound by the plan.
func (p *SignPlan) Derivation() *tss.DerivationResult {
	if p == nil || p.state == nil {
		return nil
	}
	return p.state.derivation.Clone()
}

// VerificationKeyBytes returns the Ed25519 public key used for signature verification.
func (p *SignPlan) VerificationKeyBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.verificationKey)
}

// Digest returns the canonical sign plan digest.
func (p *SignPlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil sign plan")
	}
	t := transcript.New(signPlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendUint32("threshold", uint32(p.state.threshold))
	t.AppendUint32List("parties", p.state.parties)
	t.AppendBytes("public_key", p.state.publicKey)
	t.AppendBytes("chain_code", p.state.chainCode)
	t.AppendBytes("keygen_transcript_hash", p.state.keygenHash)
	t.AppendUint32List("signers", p.state.signers)
	t.AppendBytes("context_hash", p.state.contextHash)
	appendDerivationResultTranscript(t, p.state.derivation)
	t.AppendBytes("verification_key", p.state.verificationKey)
	t.AppendBytes("message", p.state.message)
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
	_, contextHash, derivation, err := prepareSignContext(key, p.state.context)
	if err != nil {
		return err
	}
	if !bytes.Equal(contextHash, p.state.contextHash) {
		return errors.New("sign plan context hash mismatch")
	}
	if !derivation.Equal(p.state.derivation) {
		return errors.New("sign plan derivation mismatch")
	}
	if !bytes.Equal(p.state.verificationKey, derivation.ChildPublicKey) {
		return errors.New("sign plan verification key mismatch")
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
