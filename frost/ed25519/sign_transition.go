package ed25519

import (
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/planvalidation"
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
	if err := s.promotePendingPartials(); err != nil {
		return sessionEffects{}, terminalSignApplyError(signStartRound, err)
	}
	out, err := s.tryEmitPartial()
	if err != nil {
		return sessionEffects{}, terminalSignApplyError(signStartRound, err)
	}
	return sessionEffects{envelopes: out}, nil
}

func (*acceptNonceCommitmentTx) cleanupOnReject() {}

func (*acceptNonceCommitmentTx) markCommitted() {}

type acceptPartialTx struct {
	from      tss.PartyID
	partial   *fed.Scalar
	envelope  tss.Envelope
	duplicate bool
	pending   bool
	committed bool
}

func (tx *acceptPartialTx) apply(s *SignSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	if tx.pending {
		if s.pendingPartials == nil {
			s.pendingPartials = make(map[tss.PartyID]*fed.Scalar)
		}
		if s.pendingEnvelopes == nil {
			s.pendingEnvelopes = make(map[tss.PartyID]tss.Envelope)
		}
		s.pendingPartials[tx.from] = tx.partial
		s.pendingEnvelopes[tx.from] = tx.envelope.Clone()
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
		return sessionEffects{}, terminalSignApplyError(signRound2, err)
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
	if base.Round != signStartRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("commitment must be round 1"))
	}
	commitment, err := tss.DecodeBinaryValueWithLimits[nonceCommitment](base.Payload, s.limits)
	if err != nil {
		verifyKey := s.derivation.VerificationKeyBytes()
		return nil, &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: base.Round,
			Party: base.From,
			Blame: frostNonceCommitmentBlame(base, s.signers, verifyKey),
			Err:   fmt.Errorf("invalid FROST nonce commitment: %w", err),
		}
	}
	if err := planvalidation.RequireHash("sign", commitment.PlanHash, s.planHash); err != nil {
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
	if base.Round != signRound2 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("partial signature must be round 2"))
	}
	payload, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](base.Payload, s.limits)
	if err != nil {
		verifyKey := s.derivation.VerificationKeyBytes()
		return nil, &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: base.Round,
			Party: base.From,
			Blame: frostSignBlame(base, s.signers, verifyKey),
			Err:   fmt.Errorf("invalid FROST partial signature: %w", err),
		}
	}
	if err := planvalidation.RequireHash("sign", payload.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	partial := payload.Z.Scalar()
	if partial == nil {
		verifyKey := s.derivation.VerificationKeyBytes()
		return nil, &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: base.Round,
			Party: base.From,
			Blame: frostSignBlame(base, s.signers, verifyKey),
			Err:   errors.New("missing partial signature scalar"),
		}
	}
	if existing, ok := s.partials[base.From]; ok {
		defer partial.Set(fed.NewScalar())
		if existing.Equal(partial) == 1 {
			return &acceptPartialTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting partial signature"))
	}
	if existing, ok := s.pendingPartials[base.From]; ok {
		defer partial.Set(fed.NewScalar())
		if existing.Equal(partial) == 1 {
			return &acceptPartialTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting pending partial signature"))
	}
	pending := len(s.commitments) != len(s.signers)
	if !pending {
		if err := s.verifyAcceptedPartial(base, partial); err != nil {
			partial.Set(fed.NewScalar())
			return nil, err
		}
	}
	return &acceptPartialTx{
		from:     base.From,
		partial:  partial,
		envelope: base.Clone(),
		pending:  pending,
	}, nil
}

func (s *SignSession) verifyAcceptedPartial(base tss.Envelope, partial *fed.Scalar) error {
	if len(s.commitments) != len(s.signers) {
		return errors.New("cannot verify partial before all nonce commitments are available")
	}
	R, rhos, err := s.groupCommitment()
	if err != nil {
		return terminalSignApplyError(base.Round, err)
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

func terminalSignApplyError(round uint8, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*tss.ProtocolError](err); ok {
		return err
	}
	return tss.NewProtocolError(tss.ErrCodeInvariant, round, tss.BroadcastPartyId, err)
}

func (s *SignSession) promotePendingPartials() error {
	if len(s.commitments) != len(s.signers) || len(s.pendingPartials) == 0 {
		return nil
	}
	for _, id := range s.signers {
		partial, ok := s.pendingPartials[id]
		if !ok {
			continue
		}
		if err := s.verifyAcceptedPartial(s.pendingEnvelopes[id], partial); err != nil {
			return err
		}
	}
	for _, id := range s.signers {
		partial, ok := s.pendingPartials[id]
		if !ok {
			continue
		}
		s.partials[id] = partial
		s.partialEnvelopes[id] = s.pendingEnvelopes[id].Clone()
		delete(s.pendingPartials, id)
		delete(s.pendingEnvelopes, id)
	}
	return nil
}
