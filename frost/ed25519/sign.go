package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
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
	dNonce           []byte                          // Local hiding nonce bytes; secret until partial generation.
	eNonce           []byte                          // Local binding nonce bytes; secret until partial generation.
	deltaScalar      *fed.Scalar                     // Additive HD shift applied to the local signing share.
	partialSent      bool                            // Whether this party already emitted its partial signature.
	completed        bool                            // Terminal success flag after signature aggregation.
	aborted          bool                            // Terminal failure/destruction flag.
	signature        []byte                          // Final aggregate Ed25519 signature.
	commitMessage    tss.Envelope                    // Local round-1 commitment envelope for replay to callers.
	guard            *tss.EnvelopeGuard              // Transport replay, identity, and policy guard.
}

type nonceCommitment struct {
	D        []byte `wire:"1,bytes,max_bytes=point"` // hiding nonce commitment
	E        []byte `wire:"2,bytes,max_bytes=point"` // binding nonce commitment
	PlanHash []byte `wire:"3,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for nonceCommitment.
func (nonceCommitment) WireType() string { return nonceCommitmentPayloadWireType }

// WireVersion returns the wire format version for nonceCommitment.
func (nonceCommitment) WireVersion() uint16 { return tss.Version }

// MarshalJSON rejects default JSON encoding of nonce commitments.
func (nonceCommitment) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 nonce commitment must use wire encoding (MarshalBinary)")
}

type signPartialPayload struct {
	Z        []byte `wire:"1,bytes,max_bytes=scalar"`
	PlanHash []byte `wire:"2,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for signPartialPayload.
func (signPartialPayload) WireType() string { return signPartialPayloadWireType }

// WireVersion returns the wire format version for signPartialPayload.
func (signPartialPayload) WireVersion() uint16 { return tss.Version }

// MarshalJSON rejects default JSON encoding of partial signature payloads.
func (signPartialPayload) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 sign partial payload must use wire encoding (MarshalBinary)")
}

// StartSign starts a FROST signing session from a shared immutable lifecycle
// plan and local runtime configuration.
func StartSign(key *KeyShare, plan *SignPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	if key == nil || key.state == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("nil key share"))
	}
	if local.Self == 0 {
		local.Self = key.state.party
	}
	if err := key.ValidateConsistency(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if plan == nil || plan.state == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, errors.New("nil sign plan"))
	}
	if err := tss.RequireEnvelopeGuard(guard, protocol, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	// Validate the local key against the immutable plan before deriving nonce
	// material; wrong signer sets or paths must fail without mutating state.
	signers := slices.Clone(plan.state.signers)
	if err := plan.validateKey(key, local); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if len(signers) < key.state.threshold {
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
	// FROST uses two nonces per signer so the binding factor can commit to the
	// complete participant set and prevent later nonce-substitution attacks.
	dBytes, err := signingNonceGenerate(x, local.Rand)
	if err != nil {
		return nil, nil, err
	}
	eBytes, err := signingNonceGenerate(x, local.Rand)
	if err != nil {
		clear(dBytes)
		return nil, nil, err
	}

	d, err := edcurve.ScalarFromCanonical(dBytes)
	if err != nil {
		clear(dBytes)
		clear(eBytes)
		return nil, nil, err
	}
	e, err := edcurve.ScalarFromCanonical(eBytes)
	if err != nil {
		clear(dBytes)
		clear(eBytes)
		return nil, nil, err
	}

	dPoint := fed.NewIdentityPoint().ScalarBaseMult(d)
	ePoint := fed.NewIdentityPoint().ScalarBaseMult(e)
	payload, err := marshalNonceCommitmentPayloadWithLimits(nonceCommitment{D: dPoint.Bytes(), E: ePoint.Bytes(), PlanHash: planHash}, limits)
	if err != nil {
		clear(dBytes)
		clear(eBytes)
		return nil, nil, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   plan.state.sessionID,
		Round:       1,
		From:        key.state.party,
		PayloadType: payloadSignCommitment,
		Payload:     payload,
	})
	if err != nil {
		clear(dBytes)
		clear(eBytes)
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
		commitments:      map[tss.PartyID]nonceCommitment{key.state.party: {D: dPoint.Bytes(), E: ePoint.Bytes(), PlanHash: slices.Clone(planHash)}},
		partials:         make(map[tss.PartyID]*fed.Scalar),
		partialEnvelopes: make(map[tss.PartyID]tss.Envelope),
		dNonce:           dBytes,
		eNonce:           eBytes,
		deltaScalar:      deltaScalar,
		commitMessage:    env,
		guard:            guard,
	}
	out := []tss.Envelope{env}
	partial, err := s.tryEmitPartial()
	if err != nil {
		s.clearNonceBytes()
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
	return tss.ValidateInbound(s.guard, env, protocol, s.sessionID, s.key.state.parties, s.key.state.party)
}

// HandleSignMessage validates and applies one FROST signing envelope.
func (s *SignSession) HandleSignMessage(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
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
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if !tss.ContainsParty(s.signers, base.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}
	payload := base.Payload
	switch base.PayloadType {
	case payloadSignCommitment:
		if base.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("commitment must be round 1"))
		}
		p, err := unmarshalNonceCommitmentPayloadWithLimits(payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if err := requirePlanHash("sign", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		if existing, ok := s.commitments[base.From]; ok {
			if bytes.Equal(existing.D, p.D) && bytes.Equal(existing.E, p.E) && bytes.Equal(existing.PlanHash, p.PlanHash) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting nonce commitment"))
		}
		s.commitments[base.From] = p
		return s.tryEmitPartial()
	case payloadSignPartial:
		if base.Round != 2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("partial signature must be round 2"))
		}
		p, err := unmarshalSignPartialPayloadWithLimits(payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if err := requirePlanHash("sign", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		partial, err := edcurve.ScalarFromCanonical(p.Z)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if existing, ok := s.partials[base.From]; ok {
			if existing.Equal(partial) == 1 {
				if _, ok := s.partialEnvelopes[base.From]; !ok {
					s.partialEnvelopes[base.From] = base.Clone()
				}
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting partial signature"))
		}
		s.partials[base.From] = partial
		s.partialEnvelopes[base.From] = base.Clone()
		return nil, s.tryAggregate()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
	}
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
	return append([]byte(nil), s.signature...), true
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

func (s *SignSession) clearNonceBytes() {
	if s == nil {
		return
	}
	clear(s.dNonce)
	clear(s.eNonce)
	s.dNonce = nil
	s.eNonce = nil
}

func validateSignerSet(key *KeyShare, signers tss.PartySet, limits Limits) error {
	if key.state.threshold < limits.Threshold.MinProductionThreshold {
		if !limits.Threshold.AllowOneOfOne || key.state.threshold != 1 || len(key.state.parties) != 1 {
			return fmt.Errorf("key threshold %d is below production minimum %d", key.state.threshold, limits.Threshold.MinProductionThreshold)
		}
	}
	return tss.ValidateSignerSet(key.state.parties, key.state.threshold, signers, limits.ThresholdLimits())
}

// Sign runs an in-memory FROST signing exchange for tests and simple integrations.
// newInProcessGuard creates an EnvelopeGuard for in-process signing where all
// signer keys are available locally (e.g., Sign, SignWithOptions, SignDigest).
// It uses relaxed broadcast consistency since there is no actual transport layer.
// A noop ack verifier is safe here because inProcessPolicies relaxes all broadcast
// consistency requirements — VerifyFull is never invoked.
func newInProcessGuard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) *tss.EnvelopeGuard {
	g, err := tss.NewEnvelopeGuard(self, parties, protocol, sessionID, inProcessPolicies(), tss.NewInMemoryReplayCache())
	if err != nil {
		panic(err)
	}
	g.AckVerifier = &noopSignVerifier{}
	return g
}

// noopSignVerifier accepts any signature — used only by newInProcessGuard with
// relaxed policies where broadcast consistency is never required.
type noopSignVerifier struct{}

// VerifyAck implements [tss.BroadcastAckVerifier] by accepting any signature.
func (noopSignVerifier) VerifyAck(party tss.PartyID, digest [32]byte, signature []byte) error {
	return nil
}

// inProcessPolicies returns FROSTPolicies() with broadcast consistency relaxed.
func inProcessPolicies() tss.PolicySet {
	entries := FROSTPolicies().Entries()
	relaxed := make([]tss.DeliveryPolicy, len(entries))
	for i, p := range entries {
		relaxed[i] = p
		relaxed[i].BroadcastConsistency = tss.BroadcastConsistencyNone
	}
	ps, err := tss.NewPolicySet(relaxed...)
	if err != nil {
		panic(err)
	}
	return ps
}

// Sign runs an in-memory FROST signing exchange and returns the child public key and signature.
func Sign(message []byte, signers []*KeyShare, ctx tss.SigningContext) ([]byte, []byte, error) {
	return SignWithOptions(message, signers, SignOptions{Context: ctx})
}

// SignWithOptions runs an in-memory FROST signing exchange with context-bound HD derivation.
func SignWithOptions(message []byte, signers []*KeyShare, opts SignOptions) ([]byte, []byte, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make(tss.PartySet, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.ValidateConsistency(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.state.party
		shares[share.state.party] = share
	}
	ids = tss.SortParties(ids)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	round1 := make([]tss.Envelope, 0, len(signers))
	round2 := make([]tss.Envelope, 0, len(signers))
	for _, id := range ids {
		guard := newInProcessGuard(id, shares[id].state.parties, sessionID)
		plan, err := NewSignPlan(SignPlanOption{
			Key:       shares[id],
			SessionID: sessionID,
			Signers:   ids,
			Context:   opts.Context,
			Message:   message,
			Limits:    opts.Limits,
		})
		if err != nil {
			return nil, nil, err
		}
		session, out, err := StartSign(shares[id], plan, tss.LocalConfig{Self: id, Rand: opts.NonceReader}, guard)
		if err != nil {
			return nil, nil, err
		}
		sessions[id] = session
		for _, env := range out {
			if env.Round == 1 {
				round1 = append(round1, env)
			} else {
				round2 = append(round2, env)
			}
		}
	}
	for _, env := range round1 {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			inbound, err := openInProcessInbound(env)
			if err != nil {
				return nil, nil, err
			}
			out, err := sessions[id].HandleSignMessage(inbound)
			if err != nil {
				return nil, nil, err
			}
			round2 = append(round2, out...)
		}
	}
	for _, env := range round2 {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			inbound, err := openInProcessInbound(env)
			if err != nil {
				return nil, nil, err
			}
			if _, err := sessions[id].HandleSignMessage(inbound); err != nil {
				return nil, nil, err
			}
		}
	}
	sig, ok := sessions[ids[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signature not completed")
	}
	// Return the actual verification key — shifted when HD additive shift is in use.
	return sessions[ids[0]].VerificationKeyBytes(), sig, nil
}

func openInProcessInbound(env tss.Envelope) (tss.InboundEnvelope, error) {
	raw, err := env.MarshalBinary()
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	return tss.OpenEnvelope(raw, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: tss.ChannelConfidential,
		ChannelID:  "inprocess",
		PeerKeyID:  fmt.Sprintf("party-%d", env.From),
		ReceivedAt: time.Now(),
	})
}
