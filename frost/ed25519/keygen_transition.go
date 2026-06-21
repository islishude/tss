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
	pd, err := s.partyEntry(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	pd.commitments = &tx.commitments
	pd.chainCodeCommit = tx.chainCodeCommit
	out, err := s.tryComplete()
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
	pd, err := s.partyEntry(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	pd.share = tx.share
	out, err := s.tryComplete()
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
	committed    bool
}

func (tx *acceptKeygenConfirmationTx) apply(s *KeygenSession) (sessionEffects, error) {
	if tx == nil || tx.duplicate {
		return sessionEffects{}, nil
	}
	pd, err := s.partyEntry(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	pd.chainCode = bytes.Clone(tx.confirmation.ChainCode)
	pd.confirmation = tx.confirmation
	if s.pending != nil && allConfirmationsReceived(s.partyData, s.cfg.Parties) {
		return sessionEffects{}, s.finalizeConfirmedKeyShare()
	}
	return sessionEffects{}, nil
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
	pd, err := s.partyEntry(base.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	commitments := payload.Commitments.Clone()
	if pd.commitments != nil {
		if pd.commitments.Equal(commitments) && bytes.Equal(pd.chainCodeCommit, payload.ChainCodeCommit) {
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
	pd, err := s.partyEntry(base.From)
	if err != nil {
		payload.Share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if pd.share != nil {
		defer payload.Share.Destroy()
		if pd.share.Equal(payload.Share) {
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
	confirmation, err := tss.DecodeBinary[KeygenConfirmation](base.Payload)
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
	pd, err := s.partyEntry(base.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if pd.confirmation != nil {
		existing, err := pd.confirmation.MarshalBinary()
		if err == nil && bytes.Equal(existing, canonical) {
			clear(confirmation.ChainCode)
			return &acceptKeygenConfirmationTx{from: base.From, duplicate: true}, nil
		}
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, fmt.Errorf("conflicting keygen confirmation from party %d", base.From))
	}
	if !verifyChainCodeCommit(s.cfg.SessionID, base.From, confirmation.ChainCode, pd.chainCodeCommit) {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, fmt.Errorf("keygen confirmation chain code does not match round 1 commit from party %d", base.From))
	}
	if s.pending != nil {
		if err := verifyKeygenConfirmationForShare(s.pending, confirmation); err != nil {
			clear(confirmation.ChainCode)
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
	}
	return &acceptKeygenConfirmationTx{
		from:         base.From,
		confirmation: confirmation,
	}, nil
}
