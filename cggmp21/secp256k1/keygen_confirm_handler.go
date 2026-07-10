package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
)

type receivedKeygenConfirmation struct {
	env       tss.Envelope
	msg       *KeygenConfirmation
	canonical []byte
}

func (s *KeygenSession) parseKeygenConfirmation(env tss.Envelope) (*receivedKeygenConfirmation, error) {
	confirmation := new(KeygenConfirmation)
	if err := confirmation.UnmarshalBinaryWithLimits(env.Payload, s.limits); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	canonical, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical keygen confirmation"))
	}
	return &receivedKeygenConfirmation{env: env, msg: confirmation, canonical: canonical}, nil
}

func (s *KeygenSession) validateKeygenConfirmationReceipt(r *receivedKeygenConfirmation) error {
	if r == nil || r.msg == nil {
		return errors.New("nil received keygen confirmation")
	}
	if r.msg.Sender != r.env.From {
		return tss.NewProtocolError(
			tss.ErrCodeInvalidMessage,
			r.env.Round,
			r.env.From,
			fmt.Errorf("keygen confirmation sender mismatch: env from %d, payload sender %d", r.env.From, r.msg.Sender),
		)
	}
	if err := requirePlanHash("keygen confirmation", r.msg.PlanHash, s.planHash); err != nil {
		return tss.NewProtocolError(tss.ErrCodeVerification, r.env.Round, r.env.From, err)
	}
	if existing := s.pendingConfirmations[r.env.From]; existing != nil {
		encoded, marshalErr := existing.MarshalBinaryWithLimits(s.limits)
		if marshalErr == nil && bytes.Equal(encoded, r.canonical) {
			return tss.NewProtocolError(tss.ErrCodeDuplicate, r.env.Round, r.env.From, errors.New("duplicate pending keygen confirmation"))
		}
		return tss.NewProtocolError(
			tss.ErrCodeVerification,
			r.env.Round,
			r.env.From,
			fmt.Errorf("conflicting pending keygen confirmation from party %d", r.env.From),
		)
	}
	existing, ok, err := s.confirmations.confirmation(r.env.From)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, r.env.Round, r.env.From, err)
	}
	if ok {
		encoded, marshalErr := existing.MarshalBinary()
		if marshalErr == nil && bytes.Equal(encoded, r.canonical) {
			return tss.NewProtocolError(tss.ErrCodeDuplicate, r.env.Round, r.env.From, errors.New("duplicate keygen confirmation"))
		}
		return tss.NewProtocolError(
			tss.ErrCodeVerification,
			r.env.Round,
			r.env.From,
			fmt.Errorf("conflicting keygen confirmation from party %d", r.env.From),
		)
	}
	return nil
}

func (s *KeygenSession) verifyReceivedKeygenConfirmation(r *receivedKeygenConfirmation) error {
	if s.pending != nil {
		if err := verifyConfirmationBinding(s.pending, r.msg); err != nil {
			return tss.NewProtocolError(tss.ErrCodeVerification, r.env.Round, r.env.From, err)
		}
	}
	slot, err := s.round1.slot(r.env.From)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, r.env.Round, r.env.From, err)
	}
	if err := verifyConfirmationCommitRevealChainCode(
		s.cfg.SessionID,
		r.env.From,
		r.msg.ChainCode,
		slot.chainCodeCommit,
	); err != nil {
		return tss.NewProtocolError(tss.ErrCodeVerification, r.env.Round, r.env.From, err)
	}
	return nil
}

func (s *KeygenSession) buildAcceptCGGMPKeygenConfirmationTx(env tss.Envelope) (*acceptCGGMPKeygenConfirmationTx, error) {
	received, err := s.parseKeygenConfirmation(env)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			clear(received.msg.ChainCode)
		}
	}()
	if err := s.validateKeygenConfirmationReceipt(received); err != nil {
		return nil, err
	}
	slot, err := s.round1.slot(env.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if slot.chainCodeCommit == nil {
		owned = false
		return &acceptCGGMPKeygenConfirmationTx{
			from:         env.From,
			confirmation: received.msg,
			pending:      true,
		}, nil
	}
	if err := s.verifyReceivedKeygenConfirmation(received); err != nil {
		return nil, err
	}
	owned = false
	return &acceptCGGMPKeygenConfirmationTx{
		from:         env.From,
		confirmation: received.msg,
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
	received := &receivedKeygenConfirmation{
		env: tss.Envelope{
			Protocol:  tss.ProtocolCGGMP21Secp256k1,
			SessionID: s.cfg.SessionID,
			Round:     keygenConfirmationRound,
			From:      from,
		},
		msg: confirmation,
	}
	if err := s.verifyReceivedKeygenConfirmation(received); err != nil {
		return err
	}
	if err := s.confirmations.record(from, confirmation); err != nil {
		return err
	}
	delete(s.pendingConfirmations, from)
	return nil
}
