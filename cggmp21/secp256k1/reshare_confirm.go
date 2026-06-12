package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire/wireutil"
)

func (s *ReshareSession) handleReshareConfirmation(env tss.Envelope) ([]tss.Envelope, error) {
	if !s.isReceiver {
		return nil, nil
	}
	// validateInbound was already called by HandleReshareMessage.
	if env.Round != keygenConfirmationRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare confirmation in wrong round"))
	}
	confirmation, err := UnmarshalKeygenConfirmation(env.Payload)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if confirmation.Sender != env.From {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("keygen confirmation sender mismatch: env from %d, payload sender %d", env.From, confirmation.Sender))
	}
	canonical, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical reshare confirmation"))
	}
	if existing, ok := s.confirmations[env.From]; ok {
		if bytes.Equal(existing, canonical) {
			return nil, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting keygen confirmation from party %d", env.From))
	}
	if s.newShare != nil {
		if err := verifyKeygenConfirmationForShare(s.newShare, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	s.confirmations[env.From] = append([]byte(nil), canonical...)
	if s.newShare != nil && len(s.confirmations) == len(s.newParties) {
		return nil, s.finalizeConfirmedShare()
	}
	return nil, nil
}

func (s *ReshareSession) finalizeConfirmedShare() error {
	if s.newShare == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, errors.New("missing pending reshare share"))
	}
	encoded := make([][]byte, len(s.newParties))
	for i, id := range s.newParties {
		confirmation, ok := s.confirmations[id]
		if !ok {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing keygen confirmation from party %d", id))
		}
		encoded[i] = append([]byte(nil), confirmation...)
	}
	if err := verifyKeygenConfirmationSetWithoutChainCode(s.newShare, encoded); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, err)
	}
	s.newShare.KeygenConfirmations = wireutil.CloneByteSlices(encoded)
	if err := s.newShare.Validate(); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, err)
	}
	s.completed = true
	confirmationSetHash := keygenConfirmationSetHash(s.newShare.KeygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}
