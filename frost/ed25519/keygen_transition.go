package ed25519

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type acceptKeygenCommitmentsTx struct {
	from            tss.PartyID
	commitments     keygenCommitments
	chainCodeCommit []byte
	duplicate       bool
}

func (tx *acceptKeygenCommitmentsTx) apply(s *KeygenSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	slot, err := s.round1.slot(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	slot.commitments = &tx.commitments
	slot.chainCodeCommit = tx.chainCodeCommit
	if err := s.promotePendingKeygenConfirmation(tx.from); err != nil {
		return sessionEffects{}, err
	}
	out, err := s.tryAdvance()
	return sessionEffects{envelopes: out}, err
}

func (*acceptKeygenCommitmentsTx) cleanupOnReject() {}

func (*acceptKeygenCommitmentsTx) markCommitted() {}

type acceptKeygenShareTx struct {
	from      tss.PartyID
	share     *secret.Scalar
	duplicate bool
	committed bool
}

func (tx *acceptKeygenShareTx) apply(s *KeygenSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	slot, err := s.round1.slot(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	slot.share = tx.share
	out, err := s.tryAdvance()
	return sessionEffects{envelopes: out}, err
}

func (tx *acceptKeygenShareTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.share == nil {
		return
	}
	tx.share.Destroy()
	tx.share = nil
}

func (tx *acceptKeygenShareTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

type acceptKeygenConfirmationTx struct {
	from         tss.PartyID
	confirmation *KeygenConfirmation
	duplicate    bool
	pending      bool
	committed    bool
}

func (tx *acceptKeygenConfirmationTx) apply(s *KeygenSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	if tx.pending {
		if s.pendingConfirmations == nil {
			s.pendingConfirmations = make(map[tss.PartyID]*KeygenConfirmation)
		}
		s.pendingConfirmations[tx.from] = tx.confirmation
		return sessionEffects{}, nil
	}
	s.confirmations.chainCodes[tx.from] = bytes.Clone(tx.confirmation.ChainCode)
	s.confirmations.confirmations[tx.from] = tx.confirmation
	out, err := s.tryAdvance()
	return sessionEffects{envelopes: out}, err
}

func (tx *acceptKeygenConfirmationTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.confirmation == nil {
		return
	}
	clear(tx.confirmation.ChainCode)
	tx.confirmation = nil
}

func (tx *acceptKeygenConfirmationTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

func (s *KeygenSession) buildKeygenTransition(env tss.InboundEnvelope) (sessionTransition[KeygenSession], error) {
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	base := env.Envelope()
	if base.PayloadType == payloadKeygenConfirmation {
		return s.buildAcceptKeygenConfirmationTx(base)
	}
	if base.Round != keygenStartRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen only accepts round 1 messages and round 2 confirmations"))
	}
	switch base.PayloadType {
	case payloadKeygenCommitments:
		return s.buildAcceptKeygenCommitmentsTx(base)
	case payloadKeygenShare:
		return s.buildAcceptKeygenShareTx(base)
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
	}
}

func (s *KeygenSession) buildAcceptKeygenCommitmentsTx(base tss.Envelope) (*acceptKeygenCommitmentsTx, error) {
	payload, err := tss.DecodeBinaryWithLimits[keygenCommitmentsPayload](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if err := requirePlanHash("keygen", payload.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if err := payload.Commitments.ValidateThreshold(s.cfg.Threshold); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	slot, err := s.round1.slot(base.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	commitments := payload.Commitments.Clone()
	if slot.commitments != nil {
		if slot.commitments.Equal(commitments) && bytes.Equal(slot.chainCodeCommit, payload.ChainCodeCommit) {
			return &acceptKeygenCommitmentsTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting commitments"))
	}
	return &acceptKeygenCommitmentsTx{
		from:            base.From,
		commitments:     commitments,
		chainCodeCommit: bytes.Clone(payload.ChainCodeCommit),
	}, nil
}

func (s *KeygenSession) buildAcceptKeygenShareTx(base tss.Envelope) (*acceptKeygenShareTx, error) {
	payload, err := tss.DecodeBinaryWithLimits[keygenSharePayload](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if payload.Share == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("missing keygen share"))
	}
	if err := requirePlanHash("keygen", payload.PlanHash, s.planHash); err != nil {
		payload.Share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	slot, err := s.round1.slot(base.From)
	if err != nil {
		payload.Share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if slot.share != nil {
		defer payload.Share.Destroy()
		if slot.share.Equal(payload.Share) {
			return &acceptKeygenShareTx{from: base.From, duplicate: true}, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting share"))
	}
	return &acceptKeygenShareTx{
		from:  base.From,
		share: payload.Share,
	}, nil
}

func (s *KeygenSession) buildAcceptKeygenConfirmationTx(base tss.Envelope) (*acceptKeygenConfirmationTx, error) {
	if base.Round != keygenConfirmationRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen confirmation in wrong round"))
	}
	confirmation, err := tss.DecodeBinaryWithLimits[KeygenConfirmation](base.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if confirmation.Sender != base.From {
		return nil, tss.NewProtocolError(
			tss.ErrCodeInvalidMessage,
			base.Round,
			base.From,
			fmt.Errorf("keygen confirmation sender mismatch: env from %d, payload sender %d", base.From, confirmation.Sender),
		)
	}
	canonical, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if !bytes.Equal(canonical, base.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("non-canonical keygen confirmation"))
	}
	if err := requirePlanHash("keygen confirmation", confirmation.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if existing := s.pendingConfirmations[base.From]; existing != nil {
		existingRaw, marshalErr := existing.MarshalBinary()
		if marshalErr == nil && bytes.Equal(existingRaw, canonical) {
			clear(confirmation.ChainCode)
			return &acceptKeygenConfirmationTx{from: base.From, duplicate: true}, nil
		}
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, fmt.Errorf("conflicting pending keygen confirmation from party %d", base.From))
	}
	slot, err := s.round1.slot(base.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	existingConfirmation := s.confirmations.confirmations[base.From]
	if existingConfirmation != nil {
		existing, err := existingConfirmation.MarshalBinary()
		if err == nil && bytes.Equal(existing, canonical) {
			clear(confirmation.ChainCode)
			return &acceptKeygenConfirmationTx{from: base.From, duplicate: true}, nil
		}
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, fmt.Errorf("conflicting keygen confirmation from party %d", base.From))
	}
	if slot.chainCodeCommit == nil {
		return &acceptKeygenConfirmationTx{
			from:         base.From,
			confirmation: confirmation,
			pending:      true,
		}, nil
	}
	if err := verifyFROSTKeygenCommitRevealChainCode(s.cfg.SessionID, base.From, confirmation.ChainCode, slot.chainCodeCommit); err != nil {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if s.pending != nil {
		if err := verifyKeygenConfirmationForPending(s.pending, confirmation); err != nil {
			clear(confirmation.ChainCode)
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
	}
	return &acceptKeygenConfirmationTx{
		from:         base.From,
		confirmation: confirmation,
	}, nil
}

func (s *KeygenSession) promotePendingKeygenConfirmation(from tss.PartyID) error {
	confirmation := s.pendingConfirmations[from]
	if confirmation == nil {
		return nil
	}
	slot, err := s.round1.slot(from)
	if err != nil {
		return err
	}
	if slot.chainCodeCommit == nil {
		return nil
	}
	if err := verifyFROSTKeygenCommitRevealChainCode(s.cfg.SessionID, from, confirmation.ChainCode, slot.chainCodeCommit); err != nil {
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, from, err)
	}
	if s.pending != nil {
		if err := verifyKeygenConfirmationForPending(s.pending, confirmation); err != nil {
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, from, err)
		}
	}
	s.confirmations.chainCodes[from] = bytes.Clone(confirmation.ChainCode)
	s.confirmations.confirmations[from] = confirmation
	delete(s.pendingConfirmations, from)
	return nil
}
