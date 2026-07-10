package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

// SignSession tracks a two-round FROST signing exchange for one local party.
type SignSession struct {
	mu               sync.Mutex
	key              *KeyShare                       // Caller-owned long-lived key share used to sign.
	sessionID        tss.SessionID                   // Signing session ID bound into envelopes and planHash.
	log              tss.Logger                      // Optional protocol logger.
	limits           Limits                          // Local fail-closed resource policy.
	message          []byte                          // Caller message copied into the session and released on abort.
	signers          tss.PartySet                    // Canonical signer set participating in this signature.
	context          tss.SigningContext              // Normalized signing context after path resolution.
	contextHash      []byte                          // Hash binding context to nonce and partial transcripts.
	derivation       *tss.DerivationResult           // Resolved child key/path; destroyed if the session aborts.
	planHash         []byte                          // Digest every signing payload must echo.
	commitments      map[tss.PartyID]nonceCommitment // Round-1 nonce commitments by signer.
	partials         map[tss.PartyID]*fed.Scalar     // Validated partial signature scalars by signer.
	partialEnvelopes map[tss.PartyID]tss.Envelope    // Original partial envelopes retained for blame evidence.
	pendingPartials  map[tss.PartyID]*fed.Scalar     // Parsed partials awaiting the complete commitment set.
	pendingEnvelopes map[tss.PartyID]tss.Envelope    // Original envelopes for pending partials.
	dNonce           *secret.Scalar                  // Local hiding nonce; secret until partial generation.
	eNonce           *secret.Scalar                  // Local binding nonce; secret until partial generation.
	deltaScalar      *fed.Scalar                     // Additive HD shift applied to the local signing share.
	partialSent      bool                            // Whether this party already emitted its partial signature.
	completed        bool                            // Terminal success flag after signature aggregation.
	aborted          bool                            // Terminal failure/destruction flag.
	signature        []byte                          // Final aggregate Ed25519 signature.
	commitMessage    tss.Envelope                    // Local round-1 commitment envelope for replay to callers.
	guard            *tss.EnvelopeGuard              // Transport replay, identity, and policy guard.
}

type nonceCommitment struct {
	D        nonceCommitmentPoint `wire:"1,custom,len=32"` // hiding nonce commitment
	E        nonceCommitmentPoint `wire:"2,custom,len=32"` // binding nonce commitment
	PlanHash []byte               `wire:"3,bytes,len=32"`
}

// DBytes returns a caller-owned canonical hiding commitment encoding.
func (c nonceCommitment) DBytes() []byte {
	return c.D.Bytes()
}

// EBytes returns a caller-owned canonical binding commitment encoding.
func (c nonceCommitment) EBytes() []byte {
	return c.E.Bytes()
}

// Equal reports whether two nonce commitments bind the same points and plan.
func (c nonceCommitment) Equal(other nonceCommitment) bool {
	return c.D.Equal(other.D) &&
		c.E.Equal(other.E) &&
		bytes.Equal(c.PlanHash, other.PlanHash)
}

const nonceCommitmentWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for nonceCommitment.
func (nonceCommitment) WireType() string { return nonceCommitmentPayloadWireType }

// WireVersion returns the wire format version for nonceCommitment.
func (nonceCommitment) WireVersion() uint16 { return nonceCommitmentWireVersion }

// MarshalJSON rejects default JSON encoding of nonce commitments.
func (nonceCommitment) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 nonce commitment must use wire encoding (MarshalBinary)")
}

type signPartialPayload struct {
	Z        canonicalScalar `wire:"1,custom,len=32"`
	PlanHash []byte          `wire:"2,bytes,len=32"`
}

const signPartialPayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for signPartialPayload.
func (signPartialPayload) WireType() string { return signPartialPayloadWireType }

// WireVersion returns the wire format version for signPartialPayload.
func (signPartialPayload) WireVersion() uint16 { return signPartialPayloadWireVersion }

// MarshalJSON rejects default JSON encoding of partial signature payloads.
func (signPartialPayload) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 sign partial payload must use wire encoding (MarshalBinary)")
}

// SignRuntime contains this process's local execution dependencies for FROST
// signing. These values are not shared intent and are not part of the sign plan
// digest.
type SignRuntime struct {
	Local tss.LocalConfig
	Guard *tss.EnvelopeGuard
}

// StartSign starts a FROST signing session from a shared immutable lifecycle
// plan and local runtime configuration. In production, the shared plan means
// equivalent authenticated sign-run metadata, not a shared Go object. The run
// creator must distribute one signing session ID, signer set, message, and
// derivation context so every signer reconstructs an equivalent plan locally.
func StartSign(key *KeyShare, plan *SignPlan, runtime SignRuntime) (*SignSession, []tss.Envelope, error) {
	local := runtime.Local
	if key == nil || key.state == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("nil key share"))
	}
	if local.Self == 0 {
		local.Self = key.state.Party
	}
	if err := key.ValidateConsistency(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if plan == nil || plan.state == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("nil sign plan"))
	}
	if err := tss.RequireEnvelopeGuard(runtime.Guard, tss.ProtocolFROSTEd25519, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	// Validate the local key against the immutable plan before deriving nonce
	// material; wrong signer sets or paths must fail without mutating state.
	signers := slices.Clone(plan.state.signers)
	if err := plan.validateKey(key, local); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if len(signers) < key.state.Threshold {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("not enough signers"))
	}
	if !tss.ContainsParty(signers, local.Self) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("local party is not in signer set"))
	}
	limits := plan.limits
	if limits.Payload.MaxMessageBytes <= 0 {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("max message bytes must be positive"))
	}
	message := slices.Clone(plan.state.message)
	if len(message) > limits.Payload.MaxMessageBytes {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, fmt.Errorf("message too large: %d > %d", len(message), limits.Payload.MaxMessageBytes))
	}
	if err := validateSignerSet(key, signers, limits); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	var deltaScalar *fed.Scalar
	// The additive shift is the path-derived adjustment to the local secret
	// share. The public verification key remains derivation.ChildPublicKey.
	if len(plan.state.derivation.AdditiveShift) > 0 {
		shift, err := edcurve.ScalarFromCanonical(plan.state.derivation.AdditiveShift)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid additive shift: %w", err)
		}
		deltaScalar = shift
	}
	x, err := key.secretScalar()
	if err != nil {
		return nil, nil, err
	}
	defer x.Set(fed.NewScalar())
	// FROST uses two nonces per signer so the binding factor can commit to the
	// complete participant set and prevent later nonce-substitution attacks.
	d, err := signingNonceGenerate(
		x, local.Rand, plan.state.sessionID, message, plan.state.contextHash, planHash, "hiding",
	)
	if err != nil {
		return nil, nil, err
	}
	e, err := signingNonceGenerate(
		x, local.Rand, plan.state.sessionID, message, plan.state.contextHash, planHash, "binding",
	)
	if err != nil {
		d.Set(fed.NewScalar())
		return nil, nil, err
	}
	dNonce, err := newEdSecretScalarFromFed(d)
	if err != nil {
		d.Set(fed.NewScalar())
		e.Set(fed.NewScalar())
		return nil, nil, err
	}
	eNonce, err := newEdSecretScalarFromFed(e)
	if err != nil {
		dNonce.Destroy()
		d.Set(fed.NewScalar())
		e.Set(fed.NewScalar())
		return nil, nil, err
	}

	dPoint := fed.NewIdentityPoint().ScalarBaseMult(d)
	ePoint := fed.NewIdentityPoint().ScalarBaseMult(e)
	d.Set(fed.NewScalar())
	e.Set(fed.NewScalar())
	dCommitment, err := newNonceCommitmentPointFromPoint(dPoint)
	if err != nil {
		dNonce.Destroy()
		eNonce.Destroy()
		return nil, nil, err
	}
	eCommitment, err := newNonceCommitmentPointFromPoint(ePoint)
	if err != nil {
		dNonce.Destroy()
		eNonce.Destroy()
		return nil, nil, err
	}
	commitment := nonceCommitment{
		D:        dCommitment,
		E:        eCommitment,
		PlanHash: slices.Clone(planHash),
	}
	payload, err := marshalNonceCommitmentPayloadWithLimits(commitment, limits)
	if err != nil {
		dNonce.Destroy()
		eNonce.Destroy()
		return nil, nil, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   plan.state.sessionID,
		Round:       signStartRound,
		From:        key.state.Party,
		PayloadType: payloadSignCommitment,
		Payload:     payload,
	})
	if err != nil {
		dNonce.Destroy()
		eNonce.Destroy()
		return nil, nil, err
	}
	s := &SignSession{
		key:              key,
		sessionID:        plan.state.sessionID,
		log:              tss.NopLogger(),
		limits:           limits,
		message:          append([]byte(nil), message...),
		signers:          signers,
		context:          plan.state.context.Clone(),
		contextHash:      slices.Clone(plan.state.contextHash),
		derivation:       plan.state.derivation.Clone(),
		planHash:         slices.Clone(planHash),
		commitments:      map[tss.PartyID]nonceCommitment{key.state.Party: commitment},
		partials:         make(map[tss.PartyID]*fed.Scalar),
		partialEnvelopes: make(map[tss.PartyID]tss.Envelope),
		pendingPartials:  make(map[tss.PartyID]*fed.Scalar),
		pendingEnvelopes: make(map[tss.PartyID]tss.Envelope),
		dNonce:           dNonce,
		eNonce:           eNonce,
		deltaScalar:      deltaScalar,
		commitMessage:    env,
		guard:            runtime.Guard,
	}
	out := []tss.Envelope{env}
	partial, err := s.tryEmitPartial()
	if err != nil {
		s.clearNonceScalars()
		return nil, nil, err
	}
	out = append(out, partial...)
	return s, out, nil
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *SignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *SignSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolFROSTEd25519, s.sessionID, s.signers, s.key.state.Party)
}

// Handle validates and applies one FROST signing envelope.
func (s *SignSession) Handle(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(base.Round, base.From)
	}
	if s.aborted {
		return nil, abortedSessionError(base.Round, base.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	tx, err := s.buildSignTransition(env)
	if err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	defer tx.cleanupOnReject()
	effects, err := tx.apply(s)
	if err != nil {
		return nil, err
	}
	tx.markCommitted()
	return effects.envelopes, nil
}

// Signature returns the completed RFC 8032 Ed25519 signature.
func (s *SignSession) Signature() ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
		return nil, false
	}
	return bytes.Clone(s.signature), true
}

// VerifyKey returns the Ed25519 public key used for signature verification.
// When HD additive shift is in use, this is the derived (shifted) child key;
// otherwise it is the original group public key.
func (s *SignSession) VerifyKey() []byte {
	return s.VerificationKeyBytes()
}

// VerificationKeyBytes returns the Ed25519 public key used for signature verification.
func (s *SignSession) VerificationKeyBytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.derivation.VerificationKeyBytes()
}

// Context returns a copy of the signing context bound by the session.
func (s *SignSession) Context() tss.SigningContext {
	if s == nil {
		return tss.SigningContext{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.context.Clone()
}

// Derivation returns a copy of the HD derivation result bound by the session.
func (s *SignSession) Derivation() *tss.DerivationResult {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.derivation.Clone()
}

func (s *SignSession) clearNonceScalars() {
	if s == nil {
		return
	}
	if s.dNonce != nil {
		s.dNonce.Destroy()
		s.dNonce = nil
	}
	if s.eNonce != nil {
		s.eNonce.Destroy()
		s.eNonce = nil
	}
}

func validateSignerSet(key *KeyShare, signers tss.PartySet, limits Limits) error {
	if err := limits.Threshold.ValidateThreshold(key.state.Threshold, len(key.state.Parties)); err != nil {
		return err
	}
	return tss.ValidateSignerSet(key.state.Parties, key.state.Threshold, signers, limits.ThresholdLimits())
}
