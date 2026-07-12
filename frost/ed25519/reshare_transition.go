package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

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
	out, err := s.tryComplete()
	if err != nil {
		delete(s.commits, tx.from)
		return sessionEffects{}, err
	}
	return sessionEffects{envelopes: out}, nil
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
	out, err := s.tryComplete()
	if err != nil {
		delete(s.shares, tx.from)
		return sessionEffects{}, err
	}
	return sessionEffects{envelopes: out}, nil
}

type acceptReshareConfirmationTx struct {
	from         tss.PartyID
	confirmation *KeygenConfirmation
	pending      bool
	duplicate    bool
	committed    bool
}

func (tx *acceptReshareConfirmationTx) apply(s *ReshareSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	target := s.confirmations
	if tx.pending {
		target = s.pendingConfirmations
	}
	if target == nil {
		target = make(map[tss.PartyID]*KeygenConfirmation)
		if tx.pending {
			s.pendingConfirmations = target
		} else {
			s.confirmations = target
		}
	}
	target[tx.from] = tx.confirmation
	if !tx.pending {
		if err := s.tryFinalizeReshareConfirmations(); err != nil {
			delete(target, tx.from)
			return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, tx.from, err)
		}
	}
	return sessionEffects{}, nil
}

func (tx *acceptReshareConfirmationTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.confirmation == nil {
		return
	}
	clear(tx.confirmation.ChainCode)
	tx.confirmation = nil
}

func (tx *acceptReshareConfirmationTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
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
	if base.PayloadType == payloadReshareConfirmation {
		return s.buildAcceptReshareConfirmationTx(base)
	}
	if base.Round != reshareStartRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("reshare only accepts round 1 messages and round 2 confirmations"))
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

func (s *ReshareSession) buildAcceptReshareConfirmationTx(base tss.Envelope) (*acceptReshareConfirmationTx, error) {
	if base.Round != reshareConfirmationRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("reshare confirmation in wrong round"))
	}
	confirmation, err := tss.DecodeBinaryWithLimits[KeygenConfirmation](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if confirmation.Sender != base.From {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("reshare confirmation sender mismatch"))
	}
	canonical, err := confirmation.MarshalBinary()
	if err != nil {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if !bytes.Equal(canonical, base.Payload) {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("non-canonical reshare confirmation"))
	}
	if err := requirePlanHash("reshare confirmation", confirmation.PlanHash, s.planHash); err != nil {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if confirmation.SessionID != s.cfg.SessionID || confirmation.Threshold != s.newThreshold ||
		!slices.Equal(confirmation.Parties, s.newParties) || !confirmation.PublicKey.Equal(s.oldPublicKey) ||
		!bytes.Equal(confirmation.ChainCode, s.chainCode) {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("reshare confirmation does not match public plan metadata"))
	}
	for _, existing := range []map[tss.PartyID]*KeygenConfirmation{s.pendingConfirmations, s.confirmations} {
		if prior := existing[base.From]; prior != nil {
			priorRaw, marshalErr := prior.MarshalBinary()
			if marshalErr == nil && bytes.Equal(priorRaw, canonical) {
				clear(confirmation.ChainCode)
				return &acceptReshareConfirmationTx{from: base.From, duplicate: true}, nil
			}
			clear(confirmation.ChainCode)
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting reshare confirmation"))
		}
	}
	if s.confirmationBinding == nil {
		return &acceptReshareConfirmationTx{from: base.From, confirmation: confirmation, pending: true}, nil
	}
	if err := s.confirmationBinding.verify(confirmation); err != nil {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	return &acceptReshareConfirmationTx{from: base.From, confirmation: confirmation}, nil
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
