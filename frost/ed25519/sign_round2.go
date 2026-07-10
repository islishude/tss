package ed25519

import (
	stded25519 "crypto/ed25519"
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func (s *SignSession) tryAggregate() error {
	prepared, ok, err := s.prepareAggregate()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer prepared.destroy()
	s.commitAggregate(prepared)
	return nil
}

type preparedAggregateSignature struct {
	signature []byte
	committed bool
}

func (p *preparedAggregateSignature) destroy() {
	if p == nil || p.committed {
		return
	}
	clear(p.signature)
}

func (s *SignSession) prepareAggregate() (*preparedAggregateSignature, bool, error) {
	if s.completed || len(s.partials) != len(s.signers) {
		return nil, false, nil
	}
	if len(s.commitments) != len(s.signers) {
		return nil, false, nil
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		return nil, false, err
	}
	RBytes := R.Bytes()
	verifyKey := s.derivation.VerificationKeyBytes()
	c, _ := edcurve.Ed25519Challenge(RBytes, verifyKey, s.message)
	z := fed.NewScalar()
	defer z.Set(fed.NewScalar())
	for _, id := range s.signers {
		partial := s.partials[id]
		// Verify each partial before aggregation so failures can be blamed on a signer.
		if err := s.verifyPartial(id, partial, rhos[id], c); err != nil {
			blameEnv := s.partialBlameEnvelope(id, partial)
			return nil, false, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: signRound2,
				Party: id,
				Blame: frostSignBlame(blameEnv, s.signers, verifyKey),
				Err:   err,
			}
		}
		z.Add(z, partial)
	}
	zBytes := z.Bytes()
	sig := append(append([]byte(nil), RBytes...), zBytes...)
	if !stded25519.Verify(stded25519.PublicKey(verifyKey), s.message, sig) {
		return nil, false, &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: signRound2,
			Blame: frostAggregateBlame(s.sessionID, s.key.state.Party, s.signers, verifyKey, s.message, sig),
			Err:   errors.New("aggregated Ed25519 signature failed verification"),
		}
	}
	return &preparedAggregateSignature{signature: sig}, true, nil
}

func (s *SignSession) commitAggregate(p *preparedAggregateSignature) {
	if p == nil {
		return
	}
	s.signature = p.signature
	s.completed = true
	s.clearCompletedSigningState()
	p.committed = true
}

func (s *SignSession) partialBlameEnvelope(id tss.PartyID, partial *fed.Scalar) tss.Envelope {
	if env, ok := s.partialEnvelopes[id]; ok {
		return env.Clone()
	}
	zWire, err := newCanonicalScalar(partial)
	if err != nil {
		return tss.Envelope{}
	}
	payload, err := marshalSignPartialPayloadWithLimits(signPartialPayload{Z: zWire, PlanHash: s.planHash}, s.limits)
	if err != nil {
		return tss.Envelope{}
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   s.sessionID,
		Round:       signRound2,
		From:        id,
		PayloadType: payloadSignPartial,
		Payload:     payload,
	})
	if err != nil {
		return tss.Envelope{}
	}
	return env
}

func (s *SignSession) verifyPartial(id tss.PartyID, z *fed.Scalar, rho *fed.Scalar, challenge *fed.Scalar) error {
	commitment := s.commitments[id]
	D := commitment.D.Point()
	E := commitment.E.Point()
	if D == nil || E == nil {
		return errors.New("missing nonce commitment point")
	}
	YPoint, ok := s.key.verificationSharePoint(id)
	if !ok {
		return fmt.Errorf("missing verification share for %d", id)
	}
	Y := YPoint.Point()
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
	if len(s.commitments) != len(s.signers) {
		return nil, nil, errors.New("waiting for complete nonce commitments")
	}
	rhos, err := s.bindingFactors()
	if err != nil {
		return nil, nil, err
	}
	terms := make([]*fed.Point, 0, len(s.signers))
	for _, id := range s.signers {
		commitment, ok := s.commitments[id]
		if !ok {
			return nil, nil, fmt.Errorf("missing commitment for %d", id)
		}
		D := commitment.D.Point()
		E := commitment.E.Point()
		if D == nil || E == nil {
			return nil, nil, fmt.Errorf("missing commitment point for %d", id)
		}
		rhoE := fed.NewIdentityPoint().ScalarMult(rhos[id], E)
		terms = append(terms, edcurve.AddPoints(D, rhoE))
	}
	R := edcurve.AddPoints(terms...)
	if edcurve.IsIdentity(R) {
		return nil, nil, errors.New("group nonce commitment is identity")
	}
	return R, rhos, nil
}

func (s *SignSession) bindingFactors() (map[tss.PartyID]*fed.Scalar, error) {
	encodedCommitments, err := encodeGroupCommitmentList(s.signers, s.commitments)
	if err != nil {
		return nil, err
	}

	msgHash := rfc9591H4(s.message)
	commitmentHash := rfc9591H5(encodedCommitments)

	// Bind the actual verification key (shifted for HD, original otherwise)
	// so that every rho is tied to the key the verifier will use.
	verifyKey := s.derivation.VerificationKeyBytes()
	prefix := make([]byte, 0, len(verifyKey)+len(msgHash)+len(commitmentHash)+32)
	prefix = append(prefix, verifyKey...)
	prefix = append(prefix, msgHash...)
	prefix = append(prefix, commitmentHash...)

	out := make(map[tss.PartyID]*fed.Scalar, len(s.signers))
	for _, id := range s.signers {
		idEnc, err := partyIDScalarEncoding(id)
		if err != nil {
			return nil, err
		}
		input := append(append([]byte(nil), prefix...), idEnc...)
		rho, err := rfc9591H1(input)
		if err != nil {
			return nil, err
		}
		out[id] = rho
	}
	return out, nil
}
