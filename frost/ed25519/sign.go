package ed25519

import (
	stded25519 "crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/shamir"
)

// SignSession tracks a two-round FROST signing exchange for one local party.
type SignSession struct {
	key           *KeyShare
	sessionID     tss.SessionID
	message       []byte
	signers       []tss.PartyID
	commitments   map[tss.PartyID]nonceCommitment
	partials      map[tss.PartyID]*big.Int
	d             *big.Int
	e             *big.Int
	partialSent   bool
	completed     bool
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
	if err := key.Validate(); err != nil {
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
	// FROST uses two nonces per signer so the binding factor can commit to the
	// complete participant set and prevent later nonce-substitution attacks.
	_, d, err := edcurve.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	_, e, err := edcurve.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	dPoint, err := edcurve.ScalarBaseMultBig(d)
	if err != nil {
		return nil, nil, err
	}
	ePoint, err := edcurve.ScalarBaseMultBig(e)
	if err != nil {
		return nil, nil, err
	}
	payload, err := json.Marshal(nonceCommitment{D: dPoint.Bytes(), E: ePoint.Bytes()})
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
		message:       append([]byte(nil), message...),
		signers:       signers,
		commitments:   map[tss.PartyID]nonceCommitment{key.Party: {D: dPoint.Bytes(), E: ePoint.Bytes()}},
		partials:      make(map[tss.PartyID]*big.Int),
		d:             d,
		e:             e,
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
func (s *SignSession) HandleSignMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
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
		if _, ok := s.commitments[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate nonce commitment"))
		}
		var p nonceCommitment
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, err := edcurve.PointFromBytes(p.D); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, err := edcurve.PointFromBytes(p.E); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		s.commitments[env.From] = p
		return s.tryEmitPartial()
	case payloadSignPartial:
		if env.Round != 2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("partial signature must be round 2"))
		}
		if _, ok := s.partials[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate partial signature"))
		}
		var p signPartialPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		scalar, err := edcurve.ScalarFromCanonical(p.Z)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		s.partials[env.From] = edcurve.ScalarToBig(scalar)
		return nil, s.tryAggregate()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
}

// Signature returns the completed RFC 8032 Ed25519 signature.
func (s *SignSession) Signature() ([]byte, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return append([]byte(nil), s.signature...), true
}

func (s *SignSession) tryEmitPartial() ([]tss.Envelope, error) {
	if s.partialSent || len(s.commitments) != len(s.signers) {
		return nil, nil
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		return nil, err
	}
	_, c := edcurve.Ed25519Challenge(R.Bytes(), s.key.PublicKey, s.message)
	lambda, err := shamir.LagrangeCoefficient(s.key.Party, s.signers, edcurve.Order())
	if err != nil {
		return nil, err
	}
	secret, err := s.key.secretBig()
	if err != nil {
		return nil, err
	}
	// z_i = d_i + rho_i*e_i + lambda_i*c*x_i. Aggregation sums all z_i into
	// the standard Ed25519 S scalar.
	z := new(big.Int).Mul(rhos[s.key.Party], s.e)
	z.Add(z, s.d)
	lcs := new(big.Int).Mul(lambda, c)
	lcs.Mod(lcs, edcurve.Order())
	lcs.Mul(lcs, secret)
	z.Add(z, lcs)
	z.Mod(z, edcurve.Order())
	s.partials[s.key.Party] = z
	zBytes, err := scalarBytes(z)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(signPartialPayload{Z: zBytes})
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
	_, c := edcurve.Ed25519Challenge(RBytes, s.key.PublicKey, s.message)
	order := edcurve.Order()
	z := new(big.Int)
	for _, id := range s.signers {
		partial := s.partials[id]
		// Verify each partial before aggregation so failures can be blamed on a signer.
		if err := s.verifyPartial(id, partial, rhos[id], c); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 2,
				Party: id,
				Blame: &tss.Blame{Reason: "invalid FROST partial signature", Parties: []tss.PartyID{id}},
				Err:   err,
			}
		}
		z.Add(z, partial)
		z.Mod(z, order)
	}
	zBytes, err := scalarBytes(z)
	if err != nil {
		return err
	}
	sig := append(append([]byte(nil), RBytes...), zBytes...)
	if !stded25519.Verify(stded25519.PublicKey(s.key.PublicKey), s.message, sig) {
		return errors.New("aggregated Ed25519 signature failed verification")
	}
	s.signature = sig
	s.completed = true
	return nil
}

func (s *SignSession) verifyPartial(id tss.PartyID, z, rho, challenge *big.Int) error {
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
	lambda, err := shamir.LagrangeCoefficient(id, s.signers, edcurve.Order())
	if err != nil {
		return err
	}
	left, err := edcurve.ScalarBaseMultBig(z)
	if err != nil {
		return err
	}
	rhoScalar, err := edcurve.ScalarFromBig(rho)
	if err != nil {
		return err
	}
	rhoE := fed.NewIdentityPoint().ScalarMult(rhoScalar, E)
	lc := new(big.Int).Mul(lambda, challenge)
	lc.Mod(lc, edcurve.Order())
	lcScalar, err := edcurve.ScalarFromBig(lc)
	if err != nil {
		return err
	}
	lcY := fed.NewIdentityPoint().ScalarMult(lcScalar, Y)
	// Check [z_i]B = D_i + [rho_i]E_i + [lambda_i*c]Y_i.
	right := edcurve.AddPoints(D, rhoE, lcY)
	if left.Equal(right) != 1 {
		return errors.New("partial verification equation failed")
	}
	return nil
}

func (s *SignSession) groupCommitment() (*fed.Point, map[tss.PartyID]*big.Int, error) {
	rhos := make(map[tss.PartyID]*big.Int, len(s.signers))
	terms := make([]*fed.Point, 0, len(s.signers))
	for _, id := range s.signers {
		commitment, ok := s.commitments[id]
		if !ok {
			return nil, nil, fmt.Errorf("missing commitment for %d", id)
		}
		rho := bindingFactor(s.key.PublicKey, s.message, s.signers, s.commitments, id)
		rhos[id] = rho
		D, err := edcurve.PointFromBytes(commitment.D)
		if err != nil {
			return nil, nil, err
		}
		E, err := edcurve.PointFromBytes(commitment.E)
		if err != nil {
			return nil, nil, err
		}
		rhoScalar, err := edcurve.ScalarFromBig(rho)
		if err != nil {
			return nil, nil, err
		}
		rhoE := fed.NewIdentityPoint().ScalarMult(rhoScalar, E)
		terms = append(terms, edcurve.AddPoints(D, rhoE))
	}
	R := edcurve.AddPoints(terms...)
	if edcurve.IsIdentity(R) {
		return nil, nil, errors.New("group nonce commitment is identity")
	}
	return R, rhos, nil
}

func bindingFactor(publicKey, message []byte, signers []tss.PartyID, commitments map[tss.PartyID]nonceCommitment, id tss.PartyID) *big.Int {
	parts := [][]byte{
		[]byte("FROST-ED25519-SHA512-v1/binding"),
		publicKey,
		message,
	}
	for _, signer := range signers {
		// Ordered signer ids and commitments make rho deterministic across parties.
		parts = append(parts, []byte{byte(signer >> 24), byte(signer >> 16), byte(signer >> 8), byte(signer)})
		parts = append(parts, commitments[signer].D, commitments[signer].E)
	}
	parts = append(parts, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
	_, rho := edcurve.HashToScalar(parts...)
	return rho
}

func validateSignerSet(key *KeyShare, signers []tss.PartyID) error {
	seen := make(map[tss.PartyID]struct{}, len(signers))
	for _, id := range signers {
		if !tss.ContainsParty(key.Parties, id) {
			return fmt.Errorf("signer %d is not a participant", id)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate signer %d", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// Sign runs an in-memory FROST signing exchange for tests and simple integrations.
func Sign(message []byte, signers []*KeyShare) ([]byte, []byte, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.Validate(); err != nil {
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
		session, out, err := StartSign(shares[id], sessionID, ids, message)
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
	for _, id := range ids {
		if sig, ok := sessions[id].Signature(); ok {
			return signers[0].PublicKeyBytes(), sig, nil
		}
	}
	return nil, nil, errors.New("signature not completed")
}
