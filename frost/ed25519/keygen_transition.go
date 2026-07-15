package ed25519

import (
	"bytes"
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/zk/schnorred25519"
)

type acceptKeygenCommitmentsTx struct {
	from            tss.PartyID
	commitments     keygenCommitments
	chainCodeCommit []byte
	proof           *schnorred25519.Proof
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
	slot.proof = tx.proof
	if err := s.promotePendingKeygenConfirmation(tx.from); err != nil {
		return sessionEffects{}, terminalKeygenApplyError(keygenCommitmentRound, err)
	}
	out, err := s.tryAdvance()
	if err != nil {
		return sessionEffects{}, terminalKeygenApplyError(keygenCommitmentRound, err)
	}
	return sessionEffects{envelopes: out}, nil
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
	if err != nil {
		return sessionEffects{}, terminalKeygenApplyError(keygenShareRound, err)
	}
	return sessionEffects{envelopes: out}, nil
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
	if err != nil {
		return sessionEffects{}, terminalKeygenApplyError(keygenConfirmationRound, err)
	}
	return sessionEffects{envelopes: out}, nil
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
	switch base.PayloadType {
	case payloadKeygenCommitments:
		if base.Round != keygenCommitmentRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen commitments in wrong round"))
		}
		return s.buildAcceptKeygenCommitmentsTx(base)
	case payloadKeygenShare:
		if base.Round != keygenShareRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen share in wrong round"))
		}
		return s.buildAcceptKeygenShareTx(base)
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
	}
}

func (s *KeygenSession) buildAcceptKeygenCommitmentsTx(base tss.Envelope) (*acceptKeygenCommitmentsTx, error) {
	payload, err := tss.DecodeBinaryWithLimits[keygenCommitmentsPayload](base.Payload, s.limits)
	if err != nil {
		return nil, s.keygenCommitmentVerificationError(base, nil, err)
	}
	if err := requirePlanHash("keygen", payload.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if err := payload.Commitments.ValidateThreshold(s.cfg.Threshold); err != nil {
		return nil, s.keygenCommitmentVerificationError(base, payload.Commitments.BytesList(), err)
	}
	if err := verifyFROSTKeygenProof(s.cfg, s.planHash, base.From, payload.Commitments, payload.ChainCodeCommit, payload.Proof); err != nil {
		return nil, s.keygenCommitmentVerificationError(base, payload.Commitments.BytesList(), err)
	}
	if s.importPlan != nil {
		expected, ok := s.importPlan.commitmentFor(base.From)
		if !ok {
			return nil, s.keygenCommitmentVerificationError(base, payload.Commitments.BytesList(), errors.New("missing trusted-dealer commitment constraint"))
		}
		constant, pointErr := payload.Commitments.PointAt(0)
		if pointErr != nil {
			return nil, s.keygenCommitmentVerificationError(base, payload.Commitments.BytesList(), pointErr)
		}
		if !pointEqual(constant, expected.ConstantCommitment.Point()) || !bytes.Equal(payload.ChainCodeCommit, expected.ChainCodeCommit) {
			return nil, s.keygenCommitmentVerificationError(base, payload.Commitments.BytesList(), errors.New("keygen commitments do not match trusted-dealer import plan"))
		}
	}
	slot, err := s.round1.slot(base.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	commitments := payload.Commitments.Clone()
	if slot.commitments != nil {
		if slot.commitments.Equal(commitments) && bytes.Equal(slot.chainCodeCommit, payload.ChainCodeCommit) && equalFROSTKeygenProof(slot.proof, payload.Proof) {
			return &acceptKeygenCommitmentsTx{from: base.From, duplicate: true}, nil
		}
		return nil, s.keygenCommitmentVerificationError(base, payload.Commitments.BytesList(), errors.New("conflicting commitments"))
	}
	return &acceptKeygenCommitmentsTx{
		from:            base.From,
		commitments:     commitments,
		chainCodeCommit: bytes.Clone(payload.ChainCodeCommit),
		proof:           payload.Proof.Clone(),
	}, nil
}

func (s *KeygenSession) buildAcceptKeygenShareTx(base tss.Envelope) (*acceptKeygenShareTx, error) {
	payload, err := tss.DecodeBinaryWithLimits[keygenSharePayload](base.Payload, s.limits)
	if err != nil {
		return nil, s.keygenShareVerificationError(base, err)
	}
	if payload.Share == nil {
		return nil, s.keygenShareVerificationError(base, errors.New("missing keygen share"))
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
		return nil, s.keygenShareVerificationError(base, errors.New("conflicting share"))
	}
	if slot.commitments != nil {
		share, scalarErr := edScalarFromSecret(payload.Share)
		if scalarErr != nil {
			payload.Share.Destroy()
			return nil, s.keygenShareVerificationError(base, scalarErr)
		}
		verifyErr := slot.commitments.VerifyShare(s.cfg.Self, share)
		share.Set(fed.NewScalar())
		if verifyErr != nil {
			payload.Share.Destroy()
			return nil, s.keygenShareVerificationError(base, verifyErr)
		}
	}
	return &acceptKeygenShareTx{
		from:  base.From,
		share: payload.Share,
	}, nil
}

func (s *KeygenSession) keygenCommitmentVerificationError(base tss.Envelope, commitments [][]byte, err error) *tss.ProtocolError {
	return &tss.ProtocolError{
		Code:  tss.ErrCodeVerification,
		Round: keygenCommitmentRound,
		Party: base.From,
		Blame: frostKeygenCommitmentBlame(s.cfg, base, commitments),
		Err:   err,
	}
}

func (s *KeygenSession) keygenShareVerificationError(base tss.Envelope, err error) *tss.ProtocolError {
	var commitments [][]byte
	if slot, slotErr := s.round1.slot(base.From); slotErr == nil && slot.commitments != nil {
		commitments = slot.commitments.BytesList()
	}
	return &tss.ProtocolError{
		Code:  tss.ErrCodeVerification,
		Round: keygenShareRound,
		Party: base.From,
		Blame: frostKeygenBlame(s.cfg, base.From, commitments),
		Err:   err,
	}
}

func terminalKeygenApplyError(round uint8, err error) error {
	if err == nil {
		return nil
	}
	var protocolErr *tss.ProtocolError
	if errors.As(err, &protocolErr) {
		return err
	}
	return tss.NewProtocolError(tss.ErrCodeInvariant, round, tss.BroadcastPartyId, err)
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
