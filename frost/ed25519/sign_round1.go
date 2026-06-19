package ed25519

import (
	"errors"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func (s *SignSession) tryEmitPartial() ([]tss.Envelope, error) {
	if s.partialSent || len(s.commitments) != len(s.signers) {
		return nil, nil
	}
	if len(s.dNonce) == 0 || len(s.eNonce) == 0 {
		return nil, errors.New("signing nonce is unavailable")
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}
	d, err := edcurve.ScalarFromCanonical(s.dNonce)
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}
	e, err := edcurve.ScalarFromCanonical(s.eNonce)
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}
	verifyKey := s.derivation.VerificationKeyBytes()
	c, _ := edcurve.Ed25519Challenge(R.Bytes(), verifyKey, s.message)

	lambda, err := lagrangeCoefficientScalar(s.key.state.party, s.signers)
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}
	x, err := s.key.secretScalar()
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}

	// z_i = d_i + rho_i*e_i + lambda_i*c*(x_i + delta).
	// With HD additive shift delta: z_i = d_i + rho_i*e_i + lambda_i*c*x_i + lambda_i*c*delta.
	lambdaC := fed.NewScalar().Multiply(lambda, c)
	rho := rhos[s.key.state.party]
	z := fed.NewScalar().Multiply(rho, e)
	z.Add(z, d)
	lcs := fed.NewScalar().Multiply(lambdaC, x)
	z.Add(z, lcs)
	if s.deltaScalar != nil && s.deltaScalar.Equal(edcurve.ScalarZero()) != 1 {
		shiftTerm := fed.NewScalar().Multiply(lambdaC, s.deltaScalar)
		z.Add(z, shiftTerm)
	}
	s.partials[s.key.state.party] = z
	zBytes := z.Bytes()
	payload, err := marshalSignPartialPayloadWithLimits(signPartialPayload{Z: zBytes, PlanHash: s.planHash}, s.limits)
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   s.sessionID,
		Round:       2,
		From:        s.key.state.party,
		PayloadType: payloadSignPartial,
		Payload:     payload,
	})
	if err != nil {
		s.clearNonceBytes()
		return nil, err
	}
	if s.partialEnvelopes == nil {
		s.partialEnvelopes = make(map[tss.PartyID]tss.Envelope)
	}
	s.partialEnvelopes[s.key.state.party] = env.Clone()
	s.partialSent = true
	s.clearNonceBytes()
	if err := s.tryAggregate(); err != nil {
		return nil, err
	}
	return []tss.Envelope{env}, nil
}
