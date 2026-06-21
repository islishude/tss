package ed25519

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type acceptReshareCommitmentsTx struct {
	from        tss.PartyID
	commitments reshareCommitments
	duplicate   bool
}

func (tx *acceptReshareCommitmentsTx) apply(s *ReshareSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	s.commits[tx.from] = tx.commitments
	return sessionEffects{}, s.tryComplete()
}

func (*acceptReshareCommitmentsTx) cleanupOnReject() {}

func (*acceptReshareCommitmentsTx) markCommitted() {}

type acceptReshareShareTx struct {
	from      tss.PartyID
	share     *secret.Scalar
	duplicate bool
	committed bool
}

func (tx *acceptReshareShareTx) apply(s *ReshareSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	if s.shares == nil {
		s.shares = make(map[tss.PartyID]*secret.Scalar)
	}
	s.shares[tx.from] = tx.share
	return sessionEffects{}, s.tryComplete()
}

func (tx *acceptReshareShareTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.share == nil {
		return
	}
	tx.share.Destroy()
	tx.share = nil
}

func (tx *acceptReshareShareTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

func (s *ReshareSession) buildReshareTransition(env tss.InboundEnvelope) (sessionTransition[ReshareSession], error) {
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	base := env.Envelope()
	if base.Round != reshareStartRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("reshare only accepts round 1 messages"))
	}
	switch base.PayloadType {
	case payloadReshareCommitments:
		return s.buildAcceptReshareCommitmentsTx(base)
	case payloadReshareShare:
		return s.buildAcceptReshareShareTx(base)
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
	}
}

func (s *ReshareSession) buildAcceptReshareCommitmentsTx(base tss.Envelope) (*acceptReshareCommitmentsTx, error) {
	payload, err := tss.DecodeBinaryValueWithLimits[reshareCommitmentsPayload](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if err := requirePlanHash("reshare", payload.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if err := payload.Commitments.ValidateThreshold(s.newThreshold); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	commitments := payload.Commitments.Clone()
	if existing, ok := s.commits[base.From]; ok {
		if existing.Equal(commitments) {
			return &acceptReshareCommitmentsTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting reshare commitments"))
	}
	return &acceptReshareCommitmentsTx{
		from:        base.From,
		commitments: commitments,
	}, nil
}

func (s *ReshareSession) buildAcceptReshareShareTx(base tss.Envelope) (*acceptReshareShareTx, error) {
	if !s.requiresInboundShares() {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("local reshare role does not accept shares"))
	}
	payload, err := tss.DecodeBinaryValueWithLimits[reshareSharePayload](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if payload.Share == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("missing reshare share"))
	}
	if err := requirePlanHash("reshare", payload.PlanHash, s.planHash); err != nil {
		payload.Share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if existing, ok := s.shares[base.From]; ok {
		defer payload.Share.Destroy()
		if existing.Equal(payload.Share) {
			return &acceptReshareShareTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting reshare share"))
	}
	return &acceptReshareShareTx{
		from:  base.From,
		share: payload.Share,
	}, nil
}
