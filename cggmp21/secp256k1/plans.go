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
	Parties        tss.PartySet
	Threshold      int
	Limits         *Limits
	SecurityParams *SecurityParams
}

// KeygenPlan is the shared CGGMP21 keygen intent. All parties must construct the
// same plan before starting keygen.
type KeygenPlan struct {
	sessionID      tss.SessionID
	threshold      int
	parties        tss.PartySet
	limits         Limits
	securityParams SecurityParams
}

// KeygenPlanSnapshot is a caller-owned copy of keygen plan metadata.
type KeygenPlanSnapshot struct {
	SessionID      tss.SessionID
	Threshold      int
	Parties        tss.PartySet
	SecurityParams SecurityParams
}

// Clone returns a deep copy of the keygen plan snapshot.
func (s KeygenPlanSnapshot) Clone() KeygenPlanSnapshot {
	return KeygenPlanSnapshot{
		SessionID:      s.SessionID,
		Threshold:      s.Threshold,
		Parties:        s.Parties.Clone(),
		SecurityParams: s.SecurityParams,
	}
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

// Snapshot returns a caller-owned keygen plan snapshot.
func (p *KeygenPlan) Snapshot() (KeygenPlanSnapshot, bool) {
	if p == nil {
		return KeygenPlanSnapshot{}, false
	}
	return KeygenPlanSnapshot{
		SessionID:      p.sessionID,
		Threshold:      p.threshold,
		Parties:        p.parties.Clone(),
		SecurityParams: p.securityParams,
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
		Threshold:      p.threshold,
		Parties:        slices.Clone(p.parties),
		Self:           local.Self,
		SessionID:      p.sessionID,
		Rand:           local.Rand,
		Context:        local.Context,
		RoundTimeout:   local.RoundTimeout,
		Log:            local.Log,
		EnvelopeSigner: local.EnvelopeSigner,
	}, nil
}

type refreshPlanState struct {
	sessionID               tss.SessionID // Refresh protocol session; every refresh message must echo this through the envelope.
	threshold               int           // Existing signing threshold preserved by same-party refresh.
	parties                 tss.PartySet  // Canonical participant set preserved by same-party refresh.
	publicKey               []byte        // Parent group public key that must remain unchanged after refresh.
	chainCode               []byte        // HD chain code that must remain unchanged after refresh.
	paillierBits            int           // Shared modulus size for the fresh Paillier keys generated during refresh.
	oldPaillierProofSession tss.SessionID // Lifecycle session that produced the source share generation.
	oldKeygenTranscriptHash []byte        // Transcript hash that identifies the source share generation.
	oldPlanHash             []byte        // Lifecycle plan digest that authorized the source share generation.
	oldCommitmentsHash      []byte        // Hash of the source generation's group commitments.
}

// RefreshPlan is the shared CGGMP21 refresh intent. It fixes the old key
// metadata and the new session ID before any refresh messages are accepted.
type RefreshPlan struct {
	state          *refreshPlanState
	limits         Limits
	securityParams SecurityParams
}

// RefreshPlanSnapshot is a caller-owned copy of refresh plan metadata.
type RefreshPlanSnapshot struct {
	SessionID               tss.SessionID
	Threshold               int
	Parties                 tss.PartySet
	PublicKey               []byte
	ChainCode               []byte
	PaillierBits            int
	OldPaillierProofSession tss.SessionID
	OldKeygenTranscriptHash []byte
	OldPlanHash             []byte
	OldCommitmentsHash      []byte
	SecurityParams          SecurityParams
}

// Clone returns a deep copy of the refresh plan snapshot.
func (s RefreshPlanSnapshot) Clone() RefreshPlanSnapshot {
	return RefreshPlanSnapshot{
		SessionID:               s.SessionID,
		Threshold:               s.Threshold,
		Parties:                 s.Parties.Clone(),
		PublicKey:               bytes.Clone(s.PublicKey),
		ChainCode:               bytes.Clone(s.ChainCode),
		PaillierBits:            s.PaillierBits,
		OldPaillierProofSession: s.OldPaillierProofSession,
		OldKeygenTranscriptHash: bytes.Clone(s.OldKeygenTranscriptHash),
		OldPlanHash:             bytes.Clone(s.OldPlanHash),
		OldCommitmentsHash:      bytes.Clone(s.OldCommitmentsHash),
		SecurityParams:          s.SecurityParams,
	}
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
		return nil, invalidPlanConfig(oldKey.state.Party, tss.ErrInvalidSessionID)
	}
	if err := oldKey.requireMPCMaterial(limits); err != nil {
		return nil, invalidPlanConfig(oldKey.state.Party, err)
	}
	securityParams := securityParamsForArtifact(oldKey.state.SecurityParams, option.SecurityParams)
	if option.SecurityParams != nil && validSecurityParams(oldKey.state.SecurityParams) && oldKey.state.SecurityParams != *option.SecurityParams {
		return nil, invalidPlanConfig(oldKey.state.Party, errors.New("security params mismatch with old key share"))
	}
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(oldKey.state.Party, err)
	}
	paillierBits := option.PaillierBits
	if paillierBits == 0 {
		paillierBits = int(securityParams.MinPaillierBits)
	}
	if paillierBits < int(securityParams.MinPaillierBits) {
		return nil, invalidPlanConfig(oldKey.state.Party, fmt.Errorf("paillier key size %d is below security parameter minimum %d", paillierBits, securityParams.MinPaillierBits))
	}
	if limits.Paillier.MaxModulusBits > 0 && paillierBits > limits.Paillier.MaxModulusBits {
		return nil, invalidPlanConfig(oldKey.state.Party, fmt.Errorf("paillier key size %d exceeds max %d", paillierBits, limits.Paillier.MaxModulusBits))
	}
	oldCommitmentsHash, err := keygenCommitmentsHash(oldKey.state.GroupCommitments)
	if err != nil {
		return nil, invalidPlanConfig(oldKey.state.Party, fmt.Errorf("hash old group commitments: %w", err))
	}
	return &RefreshPlan{state: &refreshPlanState{
		sessionID:               option.SessionID,
		threshold:               oldKey.state.Threshold,
		parties:                 slices.Clone(oldKey.state.Parties),
		publicKey:               slices.Clone(oldKey.state.PublicKey),
		chainCode:               slices.Clone(oldKey.state.ChainCode),
		paillierBits:            paillierBits,
		oldPaillierProofSession: oldKey.state.PaillierProofSessionID,
		oldKeygenTranscriptHash: bytes.Clone(oldKey.state.KeygenTranscriptHash),
		oldPlanHash:             bytes.Clone(oldKey.state.PlanHash),
		oldCommitmentsHash:      oldCommitmentsHash,
	}, limits: limits, securityParams: securityParams}, nil
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
		PublicKey:               bytes.Clone(p.state.publicKey),
		ChainCode:               bytes.Clone(p.state.chainCode),
		PaillierBits:            p.state.paillierBits,
		OldPaillierProofSession: p.state.oldPaillierProofSession,
		OldKeygenTranscriptHash: bytes.Clone(p.state.oldKeygenTranscriptHash),
		OldPlanHash:             bytes.Clone(p.state.oldPlanHash),
		OldCommitmentsHash:      bytes.Clone(p.state.oldCommitmentsHash),
		SecurityParams:          p.securityParams,
	}, true
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
	t.AppendBytes("old_paillier_proof_session", p.state.oldPaillierProofSession[:])
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
		Threshold:      p.state.threshold,
		Parties:        slices.Clone(p.state.parties),
		Self:           local.Self,
		SessionID:      p.state.sessionID,
		Rand:           local.Rand,
		Context:        local.Context,
		RoundTimeout:   local.RoundTimeout,
		Log:            local.Log,
		EnvelopeSigner: local.EnvelopeSigner,
	}, nil
}

type presignPlanState struct {
	sessionID   tss.SessionID         // Presign protocol session; every presign envelope is scoped to it.
	threshold   int                   // Signing threshold inherited from the key share.
	parties     tss.PartySet          // Canonical key-share participant set, not just the active signer set.
	publicKey   []byte                // Parent group public key before request-time HD derivation.
	keygenHash  []byte                // Transcript hash of the keygen that produced publicKey and parties.
	signers     tss.PartySet          // Canonical subset allowed to contribute to this presign.
	context     tss.SigningContext    // Normalized signing context after path resolution.
	contextHash []byte                // Canonical hash of context, used to bind the presign across phases.
	derivation  *tss.DerivationResult // Resolved child key/path; ChildPublicKey is the verification key.
}

// PresignPlan is the shared CGGMP21 presign intent.
type PresignPlan struct {
	state          *presignPlanState
	limits         Limits
	securityParams SecurityParams
}

// PresignPlanSnapshot is a caller-owned copy of presign plan metadata.
type PresignPlanSnapshot struct {
	SessionID            tss.SessionID
	Threshold            int
	Parties              tss.PartySet
	PublicKey            []byte
	KeygenTranscriptHash []byte
	Signers              tss.PartySet
	Context              tss.SigningContext
	ContextHash          []byte
	Derivation           *tss.DerivationResult
	VerificationKey      []byte
	SecurityParams       SecurityParams
}

// Clone returns a deep copy of the presign plan snapshot.
func (s PresignPlanSnapshot) Clone() PresignPlanSnapshot {
	return PresignPlanSnapshot{
		SessionID:            s.SessionID,
		Threshold:            s.Threshold,
		Parties:              s.Parties.Clone(),
		PublicKey:            bytes.Clone(s.PublicKey),
		KeygenTranscriptHash: bytes.Clone(s.KeygenTranscriptHash),
		Signers:              s.Signers.Clone(),
		Context:              s.Context.Clone(),
		ContextHash:          bytes.Clone(s.ContextHash),
		Derivation:           s.Derivation.Clone(),
		VerificationKey:      bytes.Clone(s.VerificationKey),
		SecurityParams:       s.SecurityParams,
	}
}

// PresignPlanOption configures CGGMP21 presign plan construction.
type PresignPlanOption struct {
	Key            *KeyShare
	SessionID      tss.SessionID
	Signers        tss.PartySet
	Context        tss.SigningContext
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
		return nil, invalidPlanConfig(key.state.Party, tss.ErrInvalidSessionID)
	}
	if err := key.requireMPCMaterial(limits); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	securityParams := securityParamsForArtifact(key.state.SecurityParams, option.SecurityParams)
	if option.SecurityParams != nil && validSecurityParams(key.state.SecurityParams) && key.state.SecurityParams != *option.SecurityParams {
		return nil, invalidPlanConfig(key.state.Party, errors.New("security params mismatch with key share"))
	}
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	signers := tss.SortParties(option.Signers)
	if err := validateSignerSet(key, signers, limits); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	ctx, contextHash, derivation, err := preparePresignContext(key, option.Context)
	if err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	return &PresignPlan{state: &presignPlanState{
		sessionID:   option.SessionID,
		threshold:   key.state.Threshold,
		parties:     slices.Clone(key.state.Parties),
		publicKey:   slices.Clone(key.state.PublicKey),
		keygenHash:  slices.Clone(key.state.KeygenTranscriptHash),
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

// Threshold returns the threshold bound by the presign plan.
func (p *PresignPlan) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.threshold
}

// Snapshot returns a caller-owned presign plan snapshot.
func (p *PresignPlan) Snapshot() (PresignPlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return PresignPlanSnapshot{}, false
	}
	var verificationKey []byte
	if p.state.derivation != nil {
		verificationKey = p.state.derivation.VerificationKeyBytes()
	}
	return PresignPlanSnapshot{
		SessionID:            p.state.sessionID,
		Threshold:            p.state.threshold,
		Parties:              p.state.parties.Clone(),
		PublicKey:            bytes.Clone(p.state.publicKey),
		KeygenTranscriptHash: bytes.Clone(p.state.keygenHash),
		Signers:              p.state.signers.Clone(),
		Context:              p.state.context.Clone(),
		ContextHash:          bytes.Clone(p.state.contextHash),
		Derivation:           p.state.derivation.Clone(),
		VerificationKey:      verificationKey,
		SecurityParams:       p.securityParams,
	}, true
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
	if local.Self != key.state.Party {
		return errors.New("local self must match key share party")
	}
	if !tss.ContainsParty(p.state.signers, local.Self) {
		return errors.New("local party is not in signer set")
	}
	if p.state.threshold != key.state.Threshold ||
		!slices.Equal(p.state.parties, key.state.Parties) ||
		!bytes.Equal(p.state.publicKey, key.state.PublicKey) ||
		!bytes.Equal(p.state.keygenHash, key.state.KeygenTranscriptHash) {
		return errors.New("presign plan does not match key share")
	}
	if validSecurityParams(key.state.SecurityParams) && p.securityParams != key.state.SecurityParams {
		return errors.New("presign plan security params do not match key share")
	}
	return nil
}

type signPlanState struct {
	sessionID         tss.SessionID         // Online signing session; partial-signature envelopes are scoped to it.
	presignContentID  []byte                // Secret-tainted content commitment for the consumed presign.
	presignTranscript []byte                // Presign transcript hash carried into partial verification.
	contextHash       []byte                // Hash of the context already bound when the presign was created.
	derivation        *tss.DerivationResult // Resolved child key/path that must match the presign.
	digest            []byte                // Context-bound message digest signed by ECDSA.
	signers           tss.PartySet          // Canonical signer set participating in this online signature.
	intent            SignIntent            // Caller intent snapshot.
}

// SignPlan is the shared CGGMP21 online signing intent.
type SignPlan struct {
	state  *signPlanState
	limits Limits
}

// SignPlanSnapshot is a caller-owned copy of online signing plan metadata.
type SignPlanSnapshot struct {
	SessionID             tss.SessionID
	PresignTranscriptHash []byte
	ContextHash           []byte
	Derivation            *tss.DerivationResult
	MessageDigest         []byte
	Intent                SignIntent
}

// Clone returns a deep copy of the sign plan snapshot.
func (s SignPlanSnapshot) Clone() SignPlanSnapshot {
	return SignPlanSnapshot{
		SessionID:             s.SessionID,
		PresignTranscriptHash: bytes.Clone(s.PresignTranscriptHash),
		ContextHash:           bytes.Clone(s.ContextHash),
		Derivation:            s.Derivation.Clone(),
		MessageDigest:         bytes.Clone(s.MessageDigest),
		Intent:                s.Intent.Clone(),
	}
}

// SignPlanOption configures CGGMP21 online signing plan construction.
type SignPlanOption struct {
	Key     *KeyShare
	Presign *Presign
	Intent  SignIntent
	Limits  *Limits
}

// NewSignPlan constructs a sign plan for a key, presign, and shared intent.
func NewSignPlan(option SignPlanOption) (*SignPlan, error) {
	key := option.Key
	presign := option.Presign
	intent := option.Intent
	limits := limitsOrDefault(option.Limits)
	if key == nil || key.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil key share"))
	}
	if presign == nil || presign.state == nil {
		return nil, invalidPlanConfig(key.state.Party, errors.New("nil presign"))
	}
	if !intent.SessionID.Valid() {
		return nil, invalidPlanConfig(key.state.Party, tss.ErrInvalidSessionID)
	}
	if err := validatePresign(key, presign, limits); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	if validSecurityParams(key.state.SecurityParams) && validSecurityParams(presign.state.SecurityParams) &&
		key.state.SecurityParams != presign.state.SecurityParams {
		return nil, invalidPlanConfig(key.state.Party, errors.New("security params mismatch between key share and presign"))
	}
	if limits.Payload.MaxMessageBytes <= 0 {
		return nil, invalidPlanConfig(key.state.Party, errors.New("max message bytes must be positive"))
	}
	if len(intent.Message) > limits.Payload.MaxMessageBytes {
		return nil, invalidPlanConfig(key.state.Party, fmt.Errorf("message too large: %d > %d", len(intent.Message), limits.Payload.MaxMessageBytes))
	}
	signers := tss.SortParties(intent.Signers)
	if len(signers) == 0 {
		return nil, invalidPlanConfig(key.state.Party, errors.New("sign intent signers must not be empty"))
	}
	if !slices.Equal(signers, presign.state.Signers) {
		return nil, invalidPlanConfig(key.state.Party, errors.New("sign intent signer set mismatch"))
	}
	if err := validateSignerSet(key, signers, limits); err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	normalizedContext, contextHash, derivation, err := preparePresignContext(key, intent.Context)
	if err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	if !bytes.Equal(contextHash, presign.state.ContextHash) {
		return nil, invalidPlanConfig(key.state.Party, errors.New("presign context mismatch"))
	}
	if !derivation.Equal(presign.state.Derivation) {
		return nil, invalidPlanConfig(key.state.Party, errors.New("presign derivation mismatch"))
	}
	if !slices.Equal(derivation.ResolvedPath, presign.state.Derivation.ResolvedPath) {
		return nil, invalidPlanConfig(key.state.Party, errors.New("presign resolved path mismatch"))
	}
	normalizedIntent := SignIntent{
		SessionID: intent.SessionID,
		Context:   normalizedContext.Clone(),
		Message:   slices.Clone(intent.Message),
		Signers:   signers.Clone(),
	}
	digest := signMessageDigest(contextHash, intent.Context.MessageDomain, intent.Message)
	contentID, err := presign.contentIDWithLimits(limits)
	if err != nil {
		return nil, invalidPlanConfig(key.state.Party, err)
	}
	return &SignPlan{state: &signPlanState{
		sessionID:         intent.SessionID,
		presignContentID:  contentID,
		presignTranscript: slices.Clone(presign.state.TranscriptHash),
		contextHash:       slices.Clone(contextHash),
		derivation:        derivation.Clone(),
		digest:            slices.Clone(digest),
		signers:           signers.Clone(),
		intent:            normalizedIntent,
	}, limits: limits}, nil
}

// SessionID returns the signing session ID.
func (p *SignPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// Snapshot returns a caller-owned sign plan snapshot.
func (p *SignPlan) Snapshot() (SignPlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return SignPlanSnapshot{}, false
	}
	return SignPlanSnapshot{
		SessionID:             p.state.sessionID,
		PresignTranscriptHash: bytes.Clone(p.state.presignTranscript),
		ContextHash:           bytes.Clone(p.state.contextHash),
		Derivation:            p.state.derivation.Clone(),
		MessageDigest:         bytes.Clone(p.state.digest),
		Intent:                p.state.intent.Clone(),
	}, true
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
	t.AppendUint32List("signers", p.state.signers)
	t.AppendBytes("message_digest", p.state.digest)
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
	if local.Self != key.state.Party {
		return errors.New("local self must match key share party")
	}
	contentID, err := presign.contentIDWithLimits(p.limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(p.state.presignContentID, contentID) {
		return errors.New("sign plan presign mismatch")
	}
	if !bytes.Equal(p.state.presignTranscript, presign.state.TranscriptHash) {
		return errors.New("sign plan presign transcript mismatch")
	}
	if !bytes.Equal(p.state.contextHash, presign.state.ContextHash) {
		return errors.New("sign plan context mismatch")
	}
	if !p.state.derivation.Equal(presign.state.Derivation) {
		return errors.New("sign plan derivation mismatch")
	}
	if !slices.Equal(p.state.signers, presign.state.Signers) {
		return errors.New("sign plan signer set mismatch")
	}
	return validatePresign(key, presign, p.limits)
}

func validatePlanParties(parties tss.PartySet, threshold int, limits Limits) (tss.PartySet, error) {
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
