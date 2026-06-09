package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// SignSession tracks a two-round FROST signing exchange for one local party.
type SignSession struct {
	mu            sync.Mutex
	key           *KeyShare
	sessionID     tss.SessionID
	log           tss.Logger
	message       []byte
	signers       []tss.PartyID
	commitments   map[tss.PartyID]nonceCommitment
	partials      map[tss.PartyID]*fed.Scalar
	dNonce        []byte
	eNonce        []byte
	deltaScalar   *fed.Scalar
	verifyKey     []byte
	partialSent   bool
	completed     bool
	aborted       bool
	signature     []byte
	commitMessage tss.Envelope
	guard         *tss.EnvelopeGuard
}

type nonceCommitment struct {
	D []byte `json:"d"` // hiding nonce commitment
	E []byte `json:"e"` // binding nonce commitment
}

type signPartialPayload struct {
	Z []byte `json:"z"`
}

// StartSign starts a FROST signing session over the raw message.
func StartSign(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, message []byte) (*SignSession, []tss.Envelope, error) {
	return StartSignWithOptions(key, sessionID, signers, message, SignOptions{})
}

// StartSignWithOptions starts a FROST signing session with optional HD additive shift.
func StartSignWithOptions(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, message []byte, opts SignOptions) (*SignSession, []tss.Envelope, error) {
	if err := key.ValidateConsistency(); err != nil {
		return nil, nil, err
	}
	signers = tss.SortParties(signers)
	if len(signers) < key.Threshold {
		return nil, nil, errors.New("not enough signers")
	}
	if !tss.ContainsParty(signers, key.Party) {
		return nil, nil, errors.New("local party is not in signer set")
	}
	if err := validateSignerSet(key, signers); err != nil {
		return nil, nil, err
	}
	verifyKey := key.PublicKeyBytes()
	var deltaScalar *fed.Scalar
	if len(opts.AdditiveShift) > 0 {
		shift, err := edcurve.ScalarFromCanonical(opts.AdditiveShift)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid additive shift: %w", err)
		}
		deltaScalar = shift
		verifyKey, err = DerivePublicKey(key.PublicKey, opts.AdditiveShift)
		if err != nil {
			return nil, nil, err
		}
	}
	x, err := key.secretScalar()
	if err != nil {
		return nil, nil, err
	}
	// FROST uses two nonces per signer so the binding factor can commit to the
	// complete participant set and prevent later nonce-substitution attacks.
	dBytes, err := signingNonceGenerate(x, opts.NonceReader)
	if err != nil {
		return nil, nil, err
	}
	eBytes, err := signingNonceGenerate(x, opts.NonceReader)
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
	payload, err := marshalNonceCommitmentPayload(nonceCommitment{D: dPoint.Bytes(), E: ePoint.Bytes()})
	if err != nil {
		clear(dBytes)
		clear(eBytes)
		return nil, nil, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        key.Party,
		PayloadType: payloadSignCommitment,
		Payload:     payload,
	})
	if err != nil {
		clear(dBytes)
		clear(eBytes)
		return nil, nil, err
	}
	s := &SignSession{
		key:           key,
		sessionID:     sessionID,
		log:           tss.NopLogger(),
		message:       append([]byte(nil), message...),
		signers:       signers,
		commitments:   map[tss.PartyID]nonceCommitment{key.Party: {D: dPoint.Bytes(), E: ePoint.Bytes()}},
		partials:      make(map[tss.PartyID]*fed.Scalar),
		dNonce:        dBytes,
		eNonce:        eBytes,
		deltaScalar:   deltaScalar,
		verifyKey:     verifyKey,
		commitMessage: env,
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

// SetGuard attaches an envelope guard to the session. When set, all inbound
// envelopes are validated against protocol policies, transport authentication,
// confidentiality requirements, broadcast consistency, and replay detection.
func (s *SignSession) SetGuard(g *tss.EnvelopeGuard) {
	if s != nil {
		s.guard = g
	}
}

// NewGuard creates an EnvelopeGuard configured for this signing session.
// cache may be nil to use an in-memory cache suitable for testing.
func (s *SignSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	return tss.NewEnvelopeGuard(s.key.Party, tss.PartySet(s.key.Parties), protocol, s.sessionID, FROSTPolicies, cache)
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
// Production deployments MUST attach a guard via SetGuard before processing messages.
func (s *SignSession) validateInbound(env tss.Envelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.sessionID, s.key.Parties, s.key.Party, FROSTPolicies)
}

// HandleSignMessage validates and applies one FROST signing envelope.
func (s *SignSession) HandleSignMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.aborted = true
			s.clearNonceBytes()
		}
	}()
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	switch env.PayloadType {
	case payloadSignCommitment:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("commitment must be round 1"))
		}
		p, err := unmarshalNonceCommitmentPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if existing, ok := s.commitments[env.From]; ok {
			if bytes.Equal(existing.D, p.D) && bytes.Equal(existing.E, p.E) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting nonce commitment"))
		}
		s.commitments[env.From] = p
		return s.tryEmitPartial()
	case payloadSignPartial:
		if env.Round != 2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("partial signature must be round 2"))
		}
		p, err := unmarshalSignPartialPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		partial, err := edcurve.ScalarFromCanonical(p.Z)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if existing, ok := s.partials[env.From]; ok {
			if existing.Equal(partial) == 1 {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting partial signature"))
		}
		s.partials[env.From] = partial
		return nil, s.tryAggregate()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
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
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.verifyKey...)
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

func validateSignerSet(key *KeyShare, signers []tss.PartyID) error {
	limits := DefaultLimits()
	return tss.ValidateSignerSet(key.Parties, key.Threshold, signers, limits)
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

// inProcessPolicies returns FROSTPolicies with broadcast consistency relaxed.
func inProcessPolicies() tss.PolicySet {
	entries := FROSTPolicies.Entries()
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

// Sign runs an in-memory FROST signing exchange and returns the public key and signature.
func Sign(message []byte, signers []*KeyShare) ([]byte, []byte, error) {
	return SignWithOptions(message, signers, SignOptions{})
}

// SignWithOptions runs an in-memory FROST signing exchange with optional HD additive shift.
func SignWithOptions(message []byte, signers []*KeyShare, opts SignOptions) ([]byte, []byte, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.ValidateConsistency(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.Party
		shares[share.Party] = share
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
		session, out, err := StartSignWithOptions(shares[id], sessionID, ids, message, opts)
		if err != nil {
			return nil, nil, err
		}
		// Set up a guard for this in-process signing session.
		session.SetGuard(newInProcessGuard(id, tss.PartySet(shares[id].Parties), sessionID))
		sessions[id] = session
		for _, env := range out {
			env.Security.Authenticated = true
			env.Security.AuthenticatedParty = env.From
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
			out, err := sessions[id].HandleSignMessage(env)
			if err != nil {
				return nil, nil, err
			}
			for i := range out {
				out[i].Security.Authenticated = true
				out[i].Security.AuthenticatedParty = out[i].From
			}
			round2 = append(round2, out...)
		}
	}
	for _, env := range round2 {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if _, err := sessions[id].HandleSignMessage(env); err != nil {
				return nil, nil, err
			}
		}
	}
	sig, ok := sessions[ids[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signature not completed")
	}
	// Return the actual verification key — shifted when HD additive shift is in use.
	return sessions[ids[0]].VerifyKey(), sig, nil
}
