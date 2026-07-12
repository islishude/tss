package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
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
	Parties   tss.PartySet
	Threshold int
	Limits    *Limits
}

// KeygenPlan is the shared FROST keygen intent.
type KeygenPlan struct {
	sessionID tss.SessionID
	threshold int
	parties   tss.PartySet
	limits    Limits
}

// KeygenPlanSnapshot is a caller-owned copy of keygen plan metadata.
type KeygenPlanSnapshot struct {
	SessionID tss.SessionID
	Threshold int
	Parties   tss.PartySet
}

// Clone returns a deep copy of the keygen plan snapshot.
func (s KeygenPlanSnapshot) Clone() KeygenPlanSnapshot {
	return KeygenPlanSnapshot{
		SessionID: s.SessionID,
		Threshold: s.Threshold,
		Parties:   s.Parties.Clone(),
	}
}

// NewKeygenPlan constructs a FROST keygen plan.
func NewKeygenPlan(option KeygenPlanOption) (*KeygenPlan, error) {
	limits := limitsOrDefault(option.Limits)
	parties, err := validatePlanPartySetVerbose(option.Parties, option.Threshold, limits)
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

// Snapshot returns a caller-owned keygen plan snapshot.
func (p *KeygenPlan) Snapshot() (KeygenPlanSnapshot, bool) {
	if p == nil {
		return KeygenPlanSnapshot{}, false
	}
	return KeygenPlanSnapshot{
		SessionID: p.sessionID,
		Threshold: p.threshold,
		Parties:   p.parties.Clone(),
	}, true
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
	if _, err := validatePlanPartySetVerbose(p.parties, p.threshold, p.limits); err != nil {
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
	sessionID               tss.SessionID  // Refresh protocol session; every refresh envelope is scoped to it.
	threshold               int            // Existing signing threshold preserved by same-party refresh.
	parties                 tss.PartySet   // Canonical participant set preserved by same-party refresh.
	publicKey               publicKeyPoint // Parent group public key that must remain unchanged after refresh.
	chainCode               []byte         // HD chain code that must remain unchanged after refresh.
	oldKeygenSessionID      tss.SessionID  // Lifecycle session that produced the source share generation.
	oldKeygenTranscriptHash []byte         // Transcript hash that identifies the source share generation.
	oldPlanHash             []byte         // Plan digest that authorized the source share generation.
	oldCommitmentsHash      []byte         // Hash of the source generation's group commitments.
}

// RefreshPlan is the shared FROST same-party refresh intent.
type RefreshPlan struct {
	state  *refreshPlanState
	limits Limits
}

// RefreshPlanSnapshot is a caller-owned copy of refresh plan metadata.
type RefreshPlanSnapshot struct {
	SessionID               tss.SessionID
	Threshold               int
	Parties                 tss.PartySet
	PublicKey               []byte
	ChainCode               []byte
	OldKeygenSessionID      tss.SessionID
	OldKeygenTranscriptHash []byte
	OldPlanHash             []byte
	OldCommitmentsHash      []byte
}

// Clone returns a deep copy of the refresh plan snapshot.
func (s RefreshPlanSnapshot) Clone() RefreshPlanSnapshot {
	return RefreshPlanSnapshot{
		SessionID:               s.SessionID,
		Threshold:               s.Threshold,
		Parties:                 s.Parties.Clone(),
		PublicKey:               bytes.Clone(s.PublicKey),
		ChainCode:               bytes.Clone(s.ChainCode),
		OldKeygenSessionID:      s.OldKeygenSessionID,
		OldKeygenTranscriptHash: bytes.Clone(s.OldKeygenTranscriptHash),
		OldPlanHash:             bytes.Clone(s.OldPlanHash),
		OldCommitmentsHash:      bytes.Clone(s.OldCommitmentsHash),
	}
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
		return nil, invalidPlanConfig(oldKey.state.Party, tss.ErrInvalidSessionID)
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.Party, err)
	}
	if _, err := validatePlanPartySetVerbose(oldKey.state.Parties, oldKey.state.Threshold, limits); err != nil {
		return nil, invalidPlanConfig(oldKey.state.Party, err)
	}
	return &RefreshPlan{state: &refreshPlanState{
		sessionID:               option.SessionID,
		threshold:               oldKey.state.Threshold,
		parties:                 slices.Clone(oldKey.state.Parties),
		publicKey:               oldKey.state.PublicKey.Clone(),
		chainCode:               slices.Clone(oldKey.state.ChainCode),
		oldKeygenSessionID:      oldKey.state.KeygenSessionID,
		oldKeygenTranscriptHash: bytes.Clone(oldKey.state.KeygenTranscriptHash),
		oldPlanHash:             bytes.Clone(oldKey.state.PlanHash),
		oldCommitmentsHash:      keygenGroupCommitmentsHash(oldKey.state.GroupCommitments.BytesList()),
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

// Snapshot returns a caller-owned refresh plan snapshot.
func (p *RefreshPlan) Snapshot() (RefreshPlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return RefreshPlanSnapshot{}, false
	}
	return RefreshPlanSnapshot{
		SessionID:               p.state.sessionID,
		Threshold:               p.state.threshold,
		Parties:                 p.state.parties.Clone(),
		PublicKey:               p.state.publicKey.Bytes(),
		ChainCode:               bytes.Clone(p.state.chainCode),
		OldKeygenSessionID:      p.state.oldKeygenSessionID,
		OldKeygenTranscriptHash: bytes.Clone(p.state.oldKeygenTranscriptHash),
		OldPlanHash:             bytes.Clone(p.state.oldPlanHash),
		OldCommitmentsHash:      bytes.Clone(p.state.oldCommitmentsHash),
	}, true
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
	t.AppendBytes("public_key", p.state.publicKey.Bytes())
	t.AppendBytes("chain_code", p.state.chainCode)
	t.AppendBytes("old_keygen_session_id", p.state.oldKeygenSessionID[:])
	t.AppendBytes("old_keygen_transcript_hash", p.state.oldKeygenTranscriptHash)
	t.AppendBytes("old_plan_hash", p.state.oldPlanHash)
	t.AppendBytes("old_commitments_hash", p.state.oldCommitmentsHash)
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
	sessionID               tss.SessionID  // Reshare protocol session; all reshare envelopes are scoped to it.
	oldPublicKey            publicKeyPoint // Existing parent group public key that resharing must preserve.
	oldChainCode            []byte         // Existing HD chain code preserved across reshare.
	oldParties              tss.PartySet   // Canonical old dealer set.
	newParties              tss.PartySet   // Canonical target key-holder set.
	newThreshold            int            // Target signing threshold for the reshared key.
	oldKeygenSessionID      tss.SessionID  // Lifecycle session that produced the source share generation.
	oldKeygenTranscriptHash []byte         // Transcript hash that identifies the source share generation.
	oldPlanHash             []byte         // Plan digest that authorized the source share generation.
	oldCommitmentsHash      []byte         // Hash of the source generation's group commitments.
}

// ResharePlan is the shared FROST reshare intent.
type ResharePlan struct {
	state  *resharePlanState
	limits Limits
}

// ResharePlanSnapshot is a caller-owned copy of reshare plan metadata.
type ResharePlanSnapshot struct {
	SessionID               tss.SessionID
	OldPublicKey            []byte
	OldChainCode            []byte
	OldParties              tss.PartySet
	NewParties              tss.PartySet
	NewThreshold            int
	OldKeygenSessionID      tss.SessionID
	OldKeygenTranscriptHash []byte
	OldPlanHash             []byte
	OldCommitmentsHash      []byte
}

// Clone returns a deep copy of the reshare plan snapshot.
func (s ResharePlanSnapshot) Clone() ResharePlanSnapshot {
	return ResharePlanSnapshot{
		SessionID:               s.SessionID,
		OldPublicKey:            bytes.Clone(s.OldPublicKey),
		OldChainCode:            bytes.Clone(s.OldChainCode),
		OldParties:              s.OldParties.Clone(),
		NewParties:              s.NewParties.Clone(),
		NewThreshold:            s.NewThreshold,
		OldKeygenSessionID:      s.OldKeygenSessionID,
		OldKeygenTranscriptHash: bytes.Clone(s.OldKeygenTranscriptHash),
		OldPlanHash:             bytes.Clone(s.OldPlanHash),
		OldCommitmentsHash:      bytes.Clone(s.OldCommitmentsHash),
	}
}

// ResharePlanOption configures FROST reshare plan construction from a key share.
type ResharePlanOption struct {
	OldKey       *KeyShare
	SessionID    tss.SessionID
	NewParties   tss.PartySet
	NewThreshold int
	Limits       *Limits
}

// PublicResharePlanOption configures a public-only FROST reshare plan.
type PublicResharePlanOption struct {
	OldPublicKey            []byte
	OldChainCode            []byte
	OldParties              tss.PartySet
	OldGroupCommitments     [][]byte
	OldKeygenSessionID      tss.SessionID
	OldKeygenTranscriptHash []byte
	OldPlanHash             []byte
	SessionID               tss.SessionID
	NewParties              tss.PartySet
	NewThreshold            int
	Limits                  *Limits
}

// NewResharePlan constructs a FROST reshare plan from an old key share.
func NewResharePlan(option ResharePlanOption) (*ResharePlan, error) {
	oldKey := option.OldKey
	if oldKey == nil || oldKey.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.Party, err)
	}
	return NewPublicResharePlan(PublicResharePlanOption{
		OldPublicKey:            oldKey.state.PublicKey.Bytes(),
		OldChainCode:            oldKey.state.ChainCode,
		OldParties:              oldKey.state.Parties,
		OldGroupCommitments:     oldKey.state.GroupCommitments.BytesList(),
		OldKeygenSessionID:      oldKey.state.KeygenSessionID,
		OldKeygenTranscriptHash: oldKey.state.KeygenTranscriptHash,
		OldPlanHash:             oldKey.state.PlanHash,
		SessionID:               option.SessionID,
		NewParties:              option.NewParties,
		NewThreshold:            option.NewThreshold,
		Limits:                  option.Limits,
	})
}

// NewPublicResharePlan constructs a FROST reshare plan for new-only recipients
// that do not hold an old key share.
func NewPublicResharePlan(option PublicResharePlanOption) (*ResharePlan, error) {
	limits := limitsOrDefault(option.Limits)
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	oldPublicKey, err := newPublicKeyPointFromBytes(option.OldPublicKey)
	if err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old public key: %w", err))
	}
	if len(option.OldChainCode) != bip32util.ChainCodeSize {
		return nil, invalidPlanConfig(0, errors.New("old chain code must be 32 bytes"))
	}
	if !option.OldKeygenSessionID.Valid() {
		return nil, invalidPlanConfig(0, errors.New("invalid old keygen/lifecycle session id"))
	}
	if len(option.OldKeygenTranscriptHash) != sha256.Size {
		return nil, invalidPlanConfig(0, errors.New("old keygen transcript hash must be 32 bytes"))
	}
	if len(option.OldPlanHash) != sha256.Size {
		return nil, invalidPlanConfig(0, errors.New("old lifecycle plan hash must be 32 bytes"))
	}
	if len(option.OldGroupCommitments) > limits.Threshold.MaxThreshold {
		return nil, invalidPlanConfig(0, fmt.Errorf("old group commitments exceed local threshold limit: %d > %d", len(option.OldGroupCommitments), limits.Threshold.MaxThreshold))
	}
	oldCommitments, err := newGroupCommitmentsFromBytesList(option.OldGroupCommitments, len(option.OldGroupCommitments))
	if err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old group commitments: %w", err))
	}
	if !oldCommitments.PublicKey().Equal(oldPublicKey) {
		return nil, invalidPlanConfig(0, errors.New("old group commitments do not match old public key"))
	}
	oldParties, err := validatePlanPartySet(option.OldParties, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, fmt.Errorf("invalid old participant set: %w", err))
	}
	newParties, err := validatePlanPartySetVerbose(option.NewParties, option.NewThreshold, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	return &ResharePlan{state: &resharePlanState{
		sessionID:               option.SessionID,
		oldPublicKey:            oldPublicKey,
		oldChainCode:            slices.Clone(option.OldChainCode),
		oldParties:              oldParties,
		newParties:              newParties,
		newThreshold:            option.NewThreshold,
		oldKeygenSessionID:      option.OldKeygenSessionID,
		oldKeygenTranscriptHash: bytes.Clone(option.OldKeygenTranscriptHash),
		oldPlanHash:             bytes.Clone(option.OldPlanHash),
		oldCommitmentsHash:      keygenGroupCommitmentsHash(option.OldGroupCommitments),
	}, limits: limits}, nil
}

// SessionID returns the reshare session ID.
func (p *ResharePlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Snapshot returns a caller-owned reshare plan snapshot.
func (p *ResharePlan) Snapshot() (ResharePlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return ResharePlanSnapshot{}, false
	}
	return ResharePlanSnapshot{
		SessionID:               p.state.sessionID,
		OldPublicKey:            p.state.oldPublicKey.Bytes(),
		OldChainCode:            bytes.Clone(p.state.oldChainCode),
		OldParties:              p.state.oldParties.Clone(),
		NewParties:              p.state.newParties.Clone(),
		NewThreshold:            p.state.newThreshold,
		OldKeygenSessionID:      p.state.oldKeygenSessionID,
		OldKeygenTranscriptHash: bytes.Clone(p.state.oldKeygenTranscriptHash),
		OldPlanHash:             bytes.Clone(p.state.oldPlanHash),
		OldCommitmentsHash:      bytes.Clone(p.state.oldCommitmentsHash),
	}, true
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
	t.AppendBytes("old_public_key", p.state.oldPublicKey.Bytes())
	t.AppendBytes("old_chain_code", p.state.oldChainCode)
	t.AppendUint32List("old_parties", p.state.oldParties)
	t.AppendUint32List("new_parties", p.state.newParties)
	t.AppendUint32("new_threshold", uint32(p.state.newThreshold))
	t.AppendBytes("old_keygen_session_id", p.state.oldKeygenSessionID[:])
	t.AppendBytes("old_keygen_transcript_hash", p.state.oldKeygenTranscriptHash)
	t.AppendBytes("old_plan_hash", p.state.oldPlanHash)
	t.AppendBytes("old_commitments_hash", p.state.oldCommitmentsHash)
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
	sessionID   tss.SessionID         // Signing session; commitment and partial envelopes are scoped to it.
	threshold   int                   // Signing threshold inherited from the key share.
	parties     tss.PartySet          // Canonical full key-share participant set.
	publicKey   publicKeyPoint        // Parent group public key before request-time HD derivation.
	chainCode   []byte                // HD chain code paired with publicKey for path derivation.
	keygenHash  []byte                // Transcript hash of the keygen/reshare that produced publicKey.
	signers     tss.PartySet          // Canonical signer subset participating in this signature.
	context     tss.SigningContext    // Normalized signing context after path resolution.
	contextHash []byte                // Canonical hash binding context to nonce and partial transcripts.
	derivation  *tss.DerivationResult // Resolved child key/path; ChildPublicKey is the verification key.
	message     []byte                // Caller message copied into the plan and hashed by the signing flow.
}

// SignPlan is the shared FROST signing intent.
type SignPlan struct {
	state  *signPlanState
	limits Limits
}

// SignPlanSnapshot is a caller-owned copy of signing plan metadata.
type SignPlanSnapshot struct {
	SessionID            tss.SessionID
	Threshold            int
	Parties              tss.PartySet
	PublicKey            []byte
	ChainCode            []byte
	KeygenTranscriptHash []byte
	Signers              tss.PartySet
	Context              tss.SigningContext
	ContextHash          []byte
	Derivation           *tss.DerivationResult
	Message              []byte
	VerificationKey      []byte
}

// Clone returns a deep copy of the sign plan snapshot.
func (s SignPlanSnapshot) Clone() SignPlanSnapshot {
	return SignPlanSnapshot{
		SessionID:            s.SessionID,
		Threshold:            s.Threshold,
		Parties:              s.Parties.Clone(),
		PublicKey:            bytes.Clone(s.PublicKey),
		ChainCode:            bytes.Clone(s.ChainCode),
		KeygenTranscriptHash: bytes.Clone(s.KeygenTranscriptHash),
		Signers:              s.Signers.Clone(),
		Context:              s.Context.Clone(),
		ContextHash:          bytes.Clone(s.ContextHash),
		Derivation:           s.Derivation.Clone(),
		Message:              bytes.Clone(s.Message),
		VerificationKey:      bytes.Clone(s.VerificationKey),
	}
}

// SignPlanOption configures FROST signing plan construction.
type SignPlanOption struct {
	Key       *KeyShare
	SessionID tss.SessionID
	Signers   tss.PartySet
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
		return nil, invalidPlanConfig(key.state.Party, tss.ErrInvalidSessionID)
	}
	if err := key.ValidateConsistency(); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	signers := tss.SortParties(option.Signers)
	if err := validateSignerSet(key, signers, limits); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	context, contextHash, derivation, err := prepareSignContext(key, option.Context)
	if err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	if limits.Payload.MaxMessageBytes <= 0 {
		return nil, invalidPlanConfig(key.state.Party, errors.New("max message bytes must be positive"))
	}
	if len(option.Message) > limits.Payload.MaxMessageBytes {
		return nil, invalidPlanConfig(key.state.Party, fmt.Errorf("message too large: %d > %d", len(option.Message), limits.Payload.MaxMessageBytes))
	}
	return &SignPlan{state: &signPlanState{
		sessionID:   option.SessionID,
		threshold:   key.state.Threshold,
		parties:     slices.Clone(key.state.Parties),
		publicKey:   key.state.PublicKey.Clone(),
		chainCode:   slices.Clone(key.state.ChainCode),
		keygenHash:  slices.Clone(key.state.KeygenTranscriptHash),
		signers:     signers,
		context:     context, // already cloned in prepareSignContext
		contextHash: slices.Clone(contextHash),
		derivation:  derivation.Clone(),
		message:     slices.Clone(option.Message),
	}, limits: limits}, nil
}

// SessionID returns the signing session ID.
func (p *SignPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Snapshot returns a caller-owned signing plan snapshot.
func (p *SignPlan) Snapshot() (SignPlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return SignPlanSnapshot{}, false
	}
	verificationKey := []byte(nil)
	if p.state.derivation != nil {
		verificationKey = p.state.derivation.VerificationKeyBytes()
	}
	return SignPlanSnapshot{
		SessionID:            p.state.sessionID,
		Threshold:            p.state.threshold,
		Parties:              p.state.parties.Clone(),
		PublicKey:            p.state.publicKey.Bytes(),
		ChainCode:            bytes.Clone(p.state.chainCode),
		KeygenTranscriptHash: bytes.Clone(p.state.keygenHash),
		Signers:              p.state.signers.Clone(),
		Context:              p.state.context.Clone(),
		ContextHash:          bytes.Clone(p.state.contextHash),
		Derivation:           p.state.derivation.Clone(),
		Message:              bytes.Clone(p.state.message),
		VerificationKey:      verificationKey,
	}, true
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
	t.AppendBytes("public_key", p.state.publicKey.Bytes())
	t.AppendBytes("chain_code", p.state.chainCode)
	t.AppendBytes("keygen_transcript_hash", p.state.keygenHash)
	t.AppendUint32List("signers", p.state.signers)
	t.AppendBytes("context_hash", p.state.contextHash)
	appendDerivationResultTranscript(t, p.state.derivation)
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
	if local.Self != key.state.Party {
		return errors.New("local self must match key share party")
	}
	if !tss.ContainsParty(p.state.signers, local.Self) {
		return errors.New("local party is not in signer set")
	}
	if p.state.threshold != key.state.Threshold ||
		!slices.Equal(p.state.parties, key.state.Parties) ||
		!p.state.publicKey.Equal(key.state.PublicKey) ||
		!bytes.Equal(p.state.chainCode, key.state.ChainCode) ||
		!bytes.Equal(p.state.keygenHash, key.state.KeygenTranscriptHash) {
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
	return nil
}

func validatePlanPartySetVerbose(parties tss.PartySet, threshold int, limits Limits) (tss.PartySet, error) {
	parties, err := validatePlanPartySet(parties, limits)
	if err != nil {
		return nil, err
	}
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
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
	return parties, nil
}

func validatePlanPartySet(parties tss.PartySet, limits Limits) (tss.PartySet, error) {
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
