package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	keygenPlanDigestLabel  = "cggmp21-secp256k1-keygen-plan-v1"
	refreshPlanDigestLabel = "cggmp21-secp256k1-refresh-plan-v1"
	presignPlanDigestLabel = "cggmp21-secp256k1-presign-plan-v1"
	signPlanDigestLabel    = "cggmp21-secp256k1-sign-plan-v1"
)

var errPlanHashMismatch = errors.New("lifecycle plan hash mismatch")

// KeygenPlanOption configures CGGMP21 keygen plan construction.
//
// SessionID, Parties, Threshold, and SecurityParams are shared intent included
// in the plan digest. Limits is a local fail-closed resource policy and is
// intentionally excluded from the digest.
type KeygenPlanOption struct {
	SessionID      tss.SessionID
	Parties        []tss.PartyID
	Threshold      int
	Limits         *Limits
	SecurityParams *SecurityParams
}

// KeygenPlan is the shared CGGMP21 keygen intent. All parties must construct the
// same plan before starting keygen.
type KeygenPlan struct {
	sessionID      tss.SessionID
	threshold      int
	parties        []tss.PartyID
	limits         Limits
	securityParams SecurityParams
}

// NewKeygenPlan constructs a canonical keygen plan.
func NewKeygenPlan(option KeygenPlanOption) (*KeygenPlan, error) {
	limits := limitsOrDefault(option.Limits)
	securityParams := securityParamsOrDefault(option.SecurityParams)
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	parties, err := validatePlanParties(option.Parties, option.Threshold, limits)
	if err != nil {
		return nil, invalidPlanConfig(0, err)
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	if limits.Paillier.MaxModulusBits > 0 && int(securityParams.MinPaillierBits) > limits.Paillier.MaxModulusBits {
		return nil, invalidPlanConfig(0, fmt.Errorf("security parameter Paillier minimum %d exceeds max %d", securityParams.MinPaillierBits, limits.Paillier.MaxModulusBits))
	}
	return &KeygenPlan{
		sessionID:      option.SessionID,
		threshold:      option.Threshold,
		parties:        parties,
		limits:         limits,
		securityParams: securityParams,
	}, nil
}

// SessionID returns the protocol session ID.
func (p *KeygenPlan) SessionID() tss.SessionID {
	if p == nil {
		return tss.SessionID{}
	}
	return p.sessionID
}

// Threshold returns the signing threshold for the generated key.
func (p *KeygenPlan) Threshold() int {
	if p == nil {
		return 0
	}
	return p.threshold
}

// Parties returns a copy of the canonical keygen party set.
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
	appendSecurityParamsTranscript(t, p.securityParams)
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
	if err := p.securityParams.Validate(); err != nil {
		return err
	}
	if p.limits.Paillier.MaxModulusBits > 0 && int(p.securityParams.MinPaillierBits) > p.limits.Paillier.MaxModulusBits {
		return fmt.Errorf("security parameter Paillier minimum %d exceeds max %d", p.securityParams.MinPaillierBits, p.limits.Paillier.MaxModulusBits)
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
	sessionID    tss.SessionID // Refresh protocol session; every refresh message must echo this through the envelope.
	threshold    int           // Existing signing threshold preserved by same-party refresh.
	parties      []tss.PartyID // Canonical participant set preserved by same-party refresh.
	publicKey    []byte        // Parent group public key that must remain unchanged after refresh.
	chainCode    []byte        // HD chain code that must remain unchanged after refresh.
	paillierBits int           // Shared modulus size for the fresh Paillier keys generated during refresh.
}

// RefreshPlan is the shared CGGMP21 refresh intent. It fixes the old key
// metadata and the new session ID before any refresh messages are accepted.
type RefreshPlan struct {
	state          *refreshPlanState
	limits         Limits
	securityParams SecurityParams
}

// RefreshPlanOption configures CGGMP21 refresh plan construction.
type RefreshPlanOption struct {
	OldKey         *KeyShare
	SessionID      tss.SessionID
	PaillierBits   int
	Limits         *Limits
	SecurityParams *SecurityParams
}

// NewRefreshPlan constructs a refresh plan.
func NewRefreshPlan(option RefreshPlanOption) (*RefreshPlan, error) {
	oldKey := option.OldKey
	limits := limitsOrDefault(option.Limits)
	if oldKey == nil || oldKey.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(oldKey.state.party, tss.ErrInvalidSessionID)
	}
	if err := oldKey.requireMPCMaterial(limits); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	securityParams := securityParamsForArtifact(oldKey.state.securityParams, option.SecurityParams)
	if option.SecurityParams != nil && validSecurityParams(oldKey.state.securityParams) && oldKey.state.securityParams != *option.SecurityParams {
		return nil, invalidPlanConfig(oldKey.state.party, errors.New("security params mismatch with old key share"))
	}
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.party, err)
	}
	paillierBits := option.PaillierBits
	if paillierBits == 0 {
		paillierBits = int(securityParams.MinPaillierBits)
	}
	if paillierBits < int(securityParams.MinPaillierBits) {
		return nil, invalidPlanConfig(oldKey.state.party, fmt.Errorf("paillier key size %d is below security parameter minimum %d", paillierBits, securityParams.MinPaillierBits))
	}
	if limits.Paillier.MaxModulusBits > 0 && paillierBits > limits.Paillier.MaxModulusBits {
		return nil, invalidPlanConfig(oldKey.state.party, fmt.Errorf("paillier key size %d exceeds max %d", paillierBits, limits.Paillier.MaxModulusBits))
	}
	return &RefreshPlan{state: &refreshPlanState{
		sessionID:    option.SessionID,
		threshold:    oldKey.state.threshold,
		parties:      slices.Clone(oldKey.state.parties),
		publicKey:    slices.Clone(oldKey.state.publicKey),
		chainCode:    slices.Clone(oldKey.state.chainCode),
		paillierBits: paillierBits,
	}, limits: limits, securityParams: securityParams}, nil
}

// SessionID returns the refresh session ID.
func (p *RefreshPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Parties returns a copy of the fixed refresh party set.
func (p *RefreshPlan) Parties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.parties)
}

// Threshold returns the fixed refresh threshold.
func (p *RefreshPlan) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.threshold
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

// PaillierBits returns the shared Paillier modulus size.
func (p *RefreshPlan) PaillierBits() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.paillierBits
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
	t.AppendUint32("paillier_bits", uint32(p.state.paillierBits))
	appendSecurityParamsTranscript(t, p.securityParams)
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

type presignPlanState struct {
	sessionID   tss.SessionID         // Presign protocol session; every presign envelope is scoped to it.
	threshold   int                   // Signing threshold inherited from the key share.
	parties     []tss.PartyID         // Canonical key-share participant set, not just the active signer set.
	publicKey   []byte                // Parent group public key before request-time HD derivation.
	keygenHash  []byte                // Transcript hash of the keygen that produced publicKey and parties.
	signers     []tss.PartyID         // Canonical subset allowed to contribute to this presign.
	context     PresignContext        // Normalized signing context after path resolution.
	contextHash []byte                // Canonical hash of context, used to bind the presign across phases.
	derivation  *tss.DerivationResult // Resolved child key/path; ChildPublicKey is the verification key.
}

// PresignPlan is the shared CGGMP21 presign intent.
type PresignPlan struct {
	state          *presignPlanState
	limits         Limits
	securityParams SecurityParams
}

// PresignPlanOption configures CGGMP21 presign plan construction.
type PresignPlanOption struct {
	Key            *KeyShare
	SessionID      tss.SessionID
	Signers        []tss.PartyID
	Context        PresignContext
	Limits         *Limits
	SecurityParams *SecurityParams
}

// NewPresignPlan constructs a context-bound presign plan for a key and signer set.
func NewPresignPlan(option PresignPlanOption) (*PresignPlan, error) {
	key := option.Key
	limits := limitsOrDefault(option.Limits)
	if key == nil || key.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil key share"))
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(key.state.party, tss.ErrInvalidSessionID)
	}
	if err := key.requireMPCMaterial(limits); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	securityParams := securityParamsForArtifact(key.state.securityParams, option.SecurityParams)
	if option.SecurityParams != nil && validSecurityParams(key.state.securityParams) && key.state.securityParams != *option.SecurityParams {
		return nil, invalidPlanConfig(key.state.party, errors.New("security params mismatch with key share"))
	}
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	signers := tss.SortParties(option.Signers)
	if err := validateSignerSet(key, signers, limits); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	ctx, contextHash, derivation, err := preparePresignContext(key, option.Context)
	if err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	return &PresignPlan{state: &presignPlanState{
		sessionID:   option.SessionID,
		threshold:   key.state.threshold,
		parties:     slices.Clone(key.state.parties),
		publicKey:   slices.Clone(key.state.publicKey),
		keygenHash:  slices.Clone(key.state.keygenTranscriptHash),
		signers:     signers,
		context:     ctx.Clone(),
		contextHash: slices.Clone(contextHash),
		derivation:  derivation.Clone(),
	}, limits: limits, securityParams: securityParams}, nil
}

// SessionID returns the presign session ID.
func (p *PresignPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Signers returns a copy of the canonical signer set.
func (p *PresignPlan) Signers() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.signers)
}

// Threshold returns the threshold bound by the presign plan.
func (p *PresignPlan) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.threshold
}

// Parties returns a copy of the key participant set bound by the presign plan.
func (p *PresignPlan) Parties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.parties)
}

// PublicKeyBytes returns a copy of the group public key bound by the presign plan.
func (p *PresignPlan) PublicKeyBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.publicKey)
}

// KeygenTranscriptHashBytes returns a copy of the keygen transcript hash bound
// by the presign plan.
func (p *PresignPlan) KeygenTranscriptHashBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.keygenHash)
}

// Context returns a copy of the bound presign context.
func (p *PresignPlan) Context() PresignContext {
	if p == nil || p.state == nil {
		return PresignContext{}
	}
	return p.state.context.Clone()
}

// ContextHashBytes returns a copy of the presign context hash.
func (p *PresignPlan) ContextHashBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.contextHash)
}

// Derivation returns a copy of the HD derivation result bound by the plan.
func (p *PresignPlan) Derivation() *tss.DerivationResult {
	if p == nil || p.state == nil {
		return nil
	}
	return p.state.derivation.Clone()
}

// VerificationKeyBytes returns a copy of the child public key bound by the plan.
func (p *PresignPlan) VerificationKeyBytes() []byte {
	if p == nil || p.state == nil || p.state.derivation == nil {
		return nil
	}
	return p.state.derivation.VerificationKeyBytes()
}

// Digest returns the canonical presign plan digest.
func (p *PresignPlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil presign plan")
	}
	t := transcript.New(presignPlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendUint32("threshold", uint32(p.state.threshold))
	t.AppendUint32List("parties", p.state.parties)
	t.AppendBytes("public_key", p.state.publicKey)
	t.AppendBytes("keygen_transcript_hash", p.state.keygenHash)
	t.AppendUint32List("signers", p.state.signers)
	t.AppendBytes("context_hash", p.state.contextHash)
	appendDerivationResultTranscript(t, p.state.derivation)
	appendSecurityParamsTranscript(t, p.securityParams)
	return t.Sum(), nil
}

func (p *PresignPlan) validateKey(key *KeyShare, local tss.LocalConfig) error {
	if p == nil || p.state == nil {
		return errors.New("nil presign plan")
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
		!bytes.Equal(p.state.keygenHash, key.state.keygenTranscriptHash) {
		return errors.New("presign plan does not match key share")
	}
	if validSecurityParams(key.state.securityParams) && p.securityParams != key.state.securityParams {
		return errors.New("presign plan security params do not match key share")
	}
	return nil
}

type signPlanState struct {
	sessionID         tss.SessionID         // Online signing session; partial-signature envelopes are scoped to it.
	presignID         []byte                // Durable one-use identifier for the consumed presign.
	presignTranscript []byte                // Presign transcript hash carried into partial verification.
	contextHash       []byte                // Hash of the context already bound when the presign was created.
	derivation        *tss.DerivationResult // Resolved child key/path that must match the presign.
	digest            []byte                // Context-bound message digest signed by ECDSA.
	request           SignRequest           // Caller request snapshot; AttemptStore is kept by reference.
}

// SignPlan is the shared CGGMP21 online signing intent.
type SignPlan struct {
	state  *signPlanState
	limits Limits
}

// SignPlanOption configures CGGMP21 online signing plan construction.
type SignPlanOption struct {
	Key       *KeyShare
	Presign   *Presign
	SessionID tss.SessionID
	Request   SignRequest
	Limits    *Limits
}

// NewSignPlan constructs a sign plan for a key, presign, and request.
func NewSignPlan(option SignPlanOption) (*SignPlan, error) {
	key := option.Key
	presign := option.Presign
	request := option.Request
	limits := limitsOrDefault(option.Limits)
	if key == nil || key.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil key share"))
	}
	if presign == nil || presign.state == nil {
		return nil, invalidPlanConfig(key.state.party, errors.New("nil presign"))
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(key.state.party, tss.ErrInvalidSessionID)
	}
	if request.AttemptStore == nil {
		return nil, invalidPlanConfig(key.state.party, errors.New("sign request attempt store is required"))
	}
	if err := validatePresign(key, presign, limits); err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	if validSecurityParams(key.state.securityParams) && validSecurityParams(presign.state.securityParams) &&
		key.state.securityParams != presign.state.securityParams {
		return nil, invalidPlanConfig(key.state.party, errors.New("security params mismatch between key share and presign"))
	}
	if limits.Payload.MaxMessageBytes <= 0 {
		return nil, invalidPlanConfig(key.state.party, errors.New("max message bytes must be positive"))
	}
	if len(request.Message) > limits.Payload.MaxMessageBytes {
		return nil, invalidPlanConfig(key.state.party, fmt.Errorf("message too large: %d > %d", len(request.Message), limits.Payload.MaxMessageBytes))
	}
	normalizedContext, contextHash, derivation, err := preparePresignContext(key, request.Context)
	if err != nil {
		return nil, invalidPlanConfig(key.state.party, err)
	}
	if !bytes.Equal(contextHash, presign.state.contextHash) {
		return nil, invalidPlanConfig(key.state.party, errors.New("presign context mismatch"))
	}
	if !derivation.Equal(presign.state.derivation) {
		return nil, invalidPlanConfig(key.state.party, errors.New("presign derivation mismatch"))
	}
	if !slices.Equal(derivation.ResolvedPath, presign.state.derivation.ResolvedPath) {
		return nil, invalidPlanConfig(key.state.party, errors.New("presign resolved path mismatch"))
	}
	req := SignRequest{
		Context:             normalizedContext.Clone(),
		Message:             slices.Clone(request.Message),
		LowS:                request.LowS,
		AttemptStore:        request.AttemptStore,
		DurableStoreTimeout: request.DurableStoreTimeout,
	}
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	return &SignPlan{state: &signPlanState{
		sessionID:         option.SessionID,
		presignID:         presign.ID(),
		presignTranscript: slices.Clone(presign.state.transcriptHash),
		contextHash:       slices.Clone(contextHash),
		derivation:        derivation.Clone(),
		digest:            slices.Clone(digest),
		request:           req,
	}, limits: limits}, nil
}

// SessionID returns the signing session ID.
func (p *SignPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// PresignIDBytes returns a copy of the bound presign identifier.
func (p *SignPlan) PresignIDBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.presignID)
}

// PresignTranscriptHashBytes returns a copy of the cross-party presign
// transcript hash bound by the plan digest.
func (p *SignPlan) PresignTranscriptHashBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.presignTranscript)
}

// ContextHashBytes returns a copy of the bound presign context hash.
func (p *SignPlan) ContextHashBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.contextHash)
}

// MessageDigestBytes returns a copy of the bound signing digest.
func (p *SignPlan) MessageDigestBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return slices.Clone(p.state.digest)
}

// Request returns a copy of the bound sign request. The AttemptStore interface
// value is preserved because it is an execution dependency, not mutable data.
func (p *SignPlan) Request() SignRequest {
	if p == nil || p.state == nil {
		return SignRequest{}
	}
	return p.state.request.Clone()
}

// Digest returns the canonical sign plan digest.
func (p *SignPlan) Digest() ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil sign plan")
	}
	t := transcript.New(signPlanDigestLabel)
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendBytes("presign_transcript_hash", p.state.presignTranscript)
	t.AppendBytes("context_hash", p.state.contextHash)
	appendDerivationResultTranscript(t, p.state.derivation)
	t.AppendBytes("message_digest", p.state.digest)
	t.AppendBool("low_s", p.state.request.LowS)
	t.AppendBool("has_attempt_store", p.state.request.AttemptStore != nil)
	t.AppendUint64("durable_store_timeout_ns", uint64(durableStoreTimeout(p.state.request.DurableStoreTimeout)))
	return t.Sum(), nil
}

func (p *SignPlan) validate(key *KeyShare, presign *Presign, local tss.LocalConfig) error {
	if p == nil || p.state == nil {
		return errors.New("nil sign plan")
	}
	if key == nil || key.state == nil {
		return errors.New("nil key share")
	}
	if presign == nil || presign.state == nil {
		return errors.New("nil presign")
	}
	if local.Self != key.state.party {
		return errors.New("local self must match key share party")
	}
	if !bytes.Equal(p.state.presignID, presign.ID()) {
		return errors.New("sign plan presign mismatch")
	}
	if !bytes.Equal(p.state.presignTranscript, presign.state.transcriptHash) {
		return errors.New("sign plan presign transcript mismatch")
	}
	if !bytes.Equal(p.state.contextHash, presign.state.contextHash) {
		return errors.New("sign plan context mismatch")
	}
	if !p.state.derivation.Equal(presign.state.derivation) {
		return errors.New("sign plan derivation mismatch")
	}
	return validatePresign(key, presign, p.limits)
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
