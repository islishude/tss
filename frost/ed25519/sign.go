package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
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
	d             *fed.Scalar
	e             *fed.Scalar
	deltaScalar   *fed.Scalar
	verifyKey     []byte
	partialSent   bool
	completed     bool
	aborted       bool
	signature     []byte
	commitMessage tss.Envelope
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
	// FROST uses two nonces per signer so the binding factor can commit to the
	// complete participant set and prevent later nonce-substitution attacks.
	d, err := edcurve.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	e, err := edcurve.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	dPoint := fed.NewIdentityPoint().ScalarBaseMult(d)
	ePoint := fed.NewIdentityPoint().ScalarBaseMult(e)
	payload, err := marshalNonceCommitmentPayload(nonceCommitment{D: dPoint.Bytes(), E: ePoint.Bytes()})
	if err != nil {
		return nil, nil, err
	}
	env := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        key.Party,
		PayloadType: payloadSignCommitment,
		Payload:     payload,
	}.WithTranscriptHash()
	s := &SignSession{
		key:           key,
		sessionID:     sessionID,
		log:           tss.NopLogger(),
		message:       append([]byte(nil), message...),
		signers:       signers,
		commitments:   map[tss.PartyID]nonceCommitment{key.Party: {D: dPoint.Bytes(), E: ePoint.Bytes()}},
		partials:      make(map[tss.PartyID]*fed.Scalar),
		d:             d,
		e:             e,
		deltaScalar:   deltaScalar,
		verifyKey:     verifyKey,
		commitMessage: env,
	}
	out := []tss.Envelope{env}
	partial, err := s.tryEmitPartial()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, partial...)
	return s, out, nil
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
		}
	}()
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
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

func (s *SignSession) tryEmitPartial() ([]tss.Envelope, error) {
	if s.partialSent || len(s.commitments) != len(s.signers) {
		return nil, nil
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		return nil, err
	}
	c, _ := edcurve.Ed25519Challenge(R.Bytes(), s.verifyKey, s.message)

	lambda, err := lagrangeCoefficientScalar(s.key.Party, s.signers)
	if err != nil {
		return nil, err
	}
	x, err := s.key.secretScalar()
	if err != nil {
		return nil, err
	}

	// z_i = d_i + rho_i*e_i + lambda_i*c*(x_i + delta).
	// With HD additive shift delta: z_i = d_i + rho_i*e_i + lambda_i*c*x_i + lambda_i*c*delta.
	lambdaC := fed.NewScalar().Multiply(lambda, c)
	rho := rhos[s.key.Party]
	z := fed.NewScalar().Multiply(rho, s.e)
	z.Add(z, s.d)
	lcs := fed.NewScalar().Multiply(lambdaC, x)
	z.Add(z, lcs)
	if s.deltaScalar != nil && s.deltaScalar.Equal(edcurve.ScalarZero()) != 1 {
		shiftTerm := fed.NewScalar().Multiply(lambdaC, s.deltaScalar)
		z.Add(z, shiftTerm)
	}
	s.partials[s.key.Party] = z
	zBytes := z.Bytes()
	payload, err := marshalSignPartialPayload(signPartialPayload{Z: zBytes})
	if err != nil {
		return nil, err
	}
	env := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   s.sessionID,
		Round:       2,
		From:        s.key.Party,
		PayloadType: payloadSignPartial,
		Payload:     payload,
	}.WithTranscriptHash()
	s.partialSent = true
	if err := s.tryAggregate(); err != nil {
		return nil, err
	}
	return []tss.Envelope{env}, nil
}

func (s *SignSession) tryAggregate() error {
	if s.completed || len(s.partials) != len(s.signers) {
		return nil
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		return err
	}
	RBytes := R.Bytes()
	c, _ := edcurve.Ed25519Challenge(RBytes, s.verifyKey, s.message)
	z := fed.NewScalar()
	for _, id := range s.signers {
		partial := s.partials[id]
		// Verify each partial before aggregation so failures can be blamed on a signer.
		if err := s.verifyPartial(id, partial, rhos[id], c); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 2,
				Party: id,
				Blame: frostSignBlame(s.sessionID, s.signers, id, s.verifyKey),
				Err:   err,
			}
		}
		z.Add(z, partial)
	}
	zBytes := z.Bytes()
	sig := append(append([]byte(nil), RBytes...), zBytes...)
	if !stded25519.Verify(stded25519.PublicKey(s.verifyKey), s.message, sig) {
		return &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: 2,
			Blame: frostAggregateBlame(s.sessionID, s.signers, s.verifyKey, s.message, sig),
			Err:   errors.New("aggregated Ed25519 signature failed verification"),
		}
	}
	s.signature = sig
	s.completed = true
	return nil
}

func (s *SignSession) verifyPartial(id tss.PartyID, z *fed.Scalar, rho *fed.Scalar, challenge *fed.Scalar) error {
	commitment := s.commitments[id]
	D, err := edcurve.PointFromBytes(commitment.D)
	if err != nil {
		return err
	}
	E, err := edcurve.PointFromBytes(commitment.E)
	if err != nil {
		return err
	}
	YBytes, ok := s.key.verificationShare(id)
	if !ok {
		return fmt.Errorf("missing verification share for %d", id)
	}
	Y, err := edcurve.PointFromBytesAllowIdentity(YBytes)
	if err != nil {
		return err
	}
	if s.deltaScalar != nil && s.deltaScalar.Equal(edcurve.ScalarZero()) != 1 {
		deltaPoint := fed.NewIdentityPoint().ScalarBaseMult(s.deltaScalar)
		Y = edcurve.AddPoints(Y, deltaPoint)
	}
	lambda, err := lagrangeCoefficientScalar(id, s.signers)
	if err != nil {
		return err
	}

	// Check [z_i]B = D_i + [rho_i]E_i + [lambda_i*c]Y_i.
	left := fed.NewIdentityPoint().ScalarBaseMult(z)
	rhoE := fed.NewIdentityPoint().ScalarMult(rho, E)
	lc := fed.NewScalar().Multiply(lambda, challenge)
	lcY := fed.NewIdentityPoint().ScalarMult(lc, Y)
	right := edcurve.AddPoints(D, rhoE, lcY)
	if left.Equal(right) != 1 {
		return errors.New("partial verification equation failed")
	}
	return nil
}

func (s *SignSession) groupCommitment() (*fed.Point, map[tss.PartyID]*fed.Scalar, error) {
	rhos := make(map[tss.PartyID]*fed.Scalar, len(s.signers))
	terms := make([]*fed.Point, 0, len(s.signers))
	for _, id := range s.signers {
		commitment, ok := s.commitments[id]
		if !ok {
			return nil, nil, fmt.Errorf("missing commitment for %d", id)
		}
		rho := s.bindingFactor(id)
		rhos[id] = rho
		D, err := edcurve.PointFromBytes(commitment.D)
		if err != nil {
			return nil, nil, err
		}
		E, err := edcurve.PointFromBytes(commitment.E)
		if err != nil {
			return nil, nil, err
		}
		rhoE := fed.NewIdentityPoint().ScalarMult(rho, E)
		terms = append(terms, edcurve.AddPoints(D, rhoE))
	}
	R := edcurve.AddPoints(terms...)
	if edcurve.IsIdentity(R) {
		return nil, nil, errors.New("group nonce commitment is identity")
	}
	return R, rhos, nil
}

func (s *SignSession) bindingFactor(id tss.PartyID) *fed.Scalar {
	// Bind the actual verification key (shifted for HD, original otherwise)
	// so that the binding factor commits to the key the verifier will use.
	domain := signingBindingFactorDomain(s.sessionID, s.key.Threshold, s.key.Parties, s.signers, s.verifyKey)
	parts := [][]byte{
		[]byte(rfc9591ContextString + "rho"),
		domain,
		s.verifyKey,
		s.message,
	}
	for _, signer := range s.signers {
		// Ordered signer ids and commitments make rho deterministic across parties.
		parts = append(parts, []byte{byte(signer >> 24), byte(signer >> 16), byte(signer >> 8), byte(signer)})
		parts = append(parts, s.commitments[signer].D, s.commitments[signer].E)
	}
	parts = append(parts, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
	rho, _ := edcurve.HashToScalar(parts...)
	return rho
}

func validateSignerSet(key *KeyShare, signers []tss.PartyID) error {
	limits := tss.DefaultLimitsForAlgorithm(tss.AlgorithmFROSTEd25519)
	return tss.ValidateSignerSet(key.Parties, key.Threshold, signers, limits)
}

// Sign runs an in-memory FROST signing exchange for tests and simple integrations.
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
			out, err := sessions[id].HandleSignMessage(env)
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
