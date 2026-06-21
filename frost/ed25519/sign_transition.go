package ed25519

import (
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

type acceptNonceCommitmentTx struct {
	from       tss.PartyID
	commitment nonceCommitment
	duplicate  bool
}

func (tx *acceptNonceCommitmentTx) apply(s *SignSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	s.commitments[tx.from] = tx.commitment
	out, err := s.tryEmitPartial()
	return sessionEffects{envelopes: out}, err
}

func (*acceptNonceCommitmentTx) cleanupOnReject() {}

func (*acceptNonceCommitmentTx) markCommitted() {}

type acceptPartialTx struct {
	from      tss.PartyID
	partial   *fed.Scalar
	envelope  tss.Envelope
	duplicate bool
	committed bool
}

func (tx *acceptPartialTx) apply(s *SignSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	if s.partials == nil {
		s.partials = make(map[tss.PartyID]*fed.Scalar)
	}
	if s.partialEnvelopes == nil {
		s.partialEnvelopes = make(map[tss.PartyID]tss.Envelope)
	}
	s.partials[tx.from] = tx.partial
	s.partialEnvelopes[tx.from] = tx.envelope.Clone()
	if err := s.tryAggregate(); err != nil {
		return sessionEffects{}, err
	}
	return sessionEffects{}, nil
}

func (tx *acceptPartialTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.partial == nil {
		return
	}
	tx.partial.Set(fed.NewScalar())
	tx.partial = nil
}

func (tx *acceptPartialTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

func (s *SignSession) buildSignTransition(env tss.InboundEnvelope) (sessionTransition[SignSession], error) {
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	base := env.Envelope()
	if !tss.ContainsParty(s.signers, base.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}
	switch base.PayloadType {
	case payloadSignCommitment:
		return s.buildAcceptNonceCommitmentTx(base)
	case payloadSignPartial:
		return s.buildAcceptPartialTx(base)
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
	}
}

func (s *SignSession) buildAcceptNonceCommitmentTx(base tss.Envelope) (*acceptNonceCommitmentTx, error) {
	if base.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("commitment must be round 1"))
	}
	commitment, err := tss.DecodeBinaryValueWithLimits[nonceCommitment](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if err := requirePlanHash("sign", commitment.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if existing, ok := s.commitments[base.From]; ok {
		if existing.Equal(commitment) {
			return &acceptNonceCommitmentTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting nonce commitment"))
	}
	return &acceptNonceCommitmentTx{
		from:       base.From,
		commitment: commitment,
	}, nil
}

func (s *SignSession) buildAcceptPartialTx(base tss.Envelope) (*acceptPartialTx, error) {
	if base.Round != 2 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("partial signature must be round 2"))
	}
	payload, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if err := requirePlanHash("sign", payload.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	partial := payload.Z.Scalar()
	if partial == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("missing partial signature scalar"))
	}
	if existing, ok := s.partials[base.From]; ok {
		defer partial.Set(fed.NewScalar())
		if existing.Equal(partial) == 1 {
			return &acceptPartialTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting partial signature"))
	}
	if err := s.verifyAcceptedPartial(base, partial); err != nil {
		partial.Set(fed.NewScalar())
		return nil, err
	}
	return &acceptPartialTx{
		from:     base.From,
		partial:  partial,
		envelope: base.Clone(),
	}, nil
}

func (s *SignSession) verifyAcceptedPartial(base tss.Envelope, partial *fed.Scalar) error {
	if len(s.commitments) != len(s.signers) {
		return nil
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	verifyKey := s.derivation.VerificationKeyBytes()
	challenge, _ := edcurve.Ed25519Challenge(R.Bytes(), verifyKey, s.message)
	if err := s.verifyPartial(base.From, partial, rhos[base.From], challenge); err != nil {
		return &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: base.Round,
			Party: base.From,
			Blame: frostSignBlame(base, s.signers, verifyKey),
			Err:   err,
		}
	}
	return nil
}
