package ed25519

import (
	"errors"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

type preparedSignPartial struct {
	z         *fed.Scalar
	env       tss.Envelope
	payload   []byte
	committed bool
}

func (p *preparedSignPartial) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.z != nil {
		p.z.Set(fed.NewScalar())
		p.z = nil
	}
	clear(p.payload)
}

func (s *SignSession) prepareLocalPartial() (*preparedSignPartial, bool, error) {
	if s.partialSent || len(s.commitments) != len(s.signers) {
		return nil, false, nil
	}
	if s.dNonce == nil || s.eNonce == nil {
		return nil, false, errors.New("signing nonce is unavailable")
	}
	cleanup := newCleanupStack()
	defer cleanup.run()

	R, rhos, err := s.groupCommitment()
	if err != nil {
		return nil, false, err
	}
	d, err := edScalarFromSecret(s.dNonce)
	if err != nil {
		return nil, false, err
	}
	defer d.Set(fed.NewScalar())
	e, err := edScalarFromSecret(s.eNonce)
	if err != nil {
		return nil, false, err
	}
	defer e.Set(fed.NewScalar())
	verifyKey := s.derivation.VerificationKeyBytes()
	c, _ := edcurve.Ed25519Challenge(R.Bytes(), verifyKey, s.message)

	lambda, err := lagrangeCoefficientScalar(s.key.state.party, s.signers)
	if err != nil {
		return nil, false, err
	}
	x, err := s.key.secretScalar()
	if err != nil {
		return nil, false, err
	}
	defer x.Set(fed.NewScalar())

	// z_i = d_i + rho_i*e_i + lambda_i*c*(x_i + delta).
	// With HD additive shift delta: z_i = d_i + rho_i*e_i + lambda_i*c*x_i + lambda_i*c*delta.
	lambdaC := fed.NewScalar().Multiply(lambda, c)
	defer lambdaC.Set(fed.NewScalar())
	rho := rhos[s.key.state.party]
	z := fed.NewScalar().Multiply(rho, e)
	cleanup.add(func() { z.Set(fed.NewScalar()) })
	z.Add(z, d)
	lcs := fed.NewScalar().Multiply(lambdaC, x)
	defer lcs.Set(fed.NewScalar())
	z.Add(z, lcs)
	if s.deltaScalar != nil && s.deltaScalar.Equal(edcurve.ScalarZero()) != 1 {
		shiftTerm := fed.NewScalar().Multiply(lambdaC, s.deltaScalar)
		defer shiftTerm.Set(fed.NewScalar())
		z.Add(z, shiftTerm)
	}
	zWire, err := newCanonicalScalar(z)
	if err != nil {
		return nil, false, err
	}
	payload, err := marshalSignPartialPayloadWithLimits(signPartialPayload{Z: zWire, PlanHash: s.planHash}, s.limits)
	if err != nil {
		return nil, false, err
	}
	cleanup.add(func() { clear(payload) })
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   s.sessionID,
		Round:       2,
		From:        s.key.state.party,
		PayloadType: payloadSignPartial,
		Payload:     payload,
	})
	if err != nil {
		return nil, false, err
	}
	prepared := &preparedSignPartial{
		z:       z,
		env:     env,
		payload: payload,
	}
	cleanup.disarm()
	return prepared, true, nil
}

func (s *SignSession) commitLocalPartial(p *preparedSignPartial) sessionEffects {
	if p == nil {
		return sessionEffects{}
	}
	if s.partials == nil {
		s.partials = make(map[tss.PartyID]*fed.Scalar)
	}
	if s.partialEnvelopes == nil {
		s.partialEnvelopes = make(map[tss.PartyID]tss.Envelope)
	}
	self := s.key.state.party
	s.partials[self] = p.z
	s.partialEnvelopes[self] = p.env.Clone()
	s.partialSent = true
	s.clearNonceScalars()
	p.committed = true
	return sessionEffects{envelopes: []tss.Envelope{p.env}}
}
