package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire/wireutil"
)

func (s *RefreshSession) handleRefreshConfirmation(env tss.Envelope) ([]tss.Envelope, error) {
	if env.Round != keygenConfirmationRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh confirmation in wrong round"))
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
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical refresh confirmation"))
	}
	if err := requirePlanHash("refresh confirmation", confirmation.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if existing, ok := s.confirmations[env.From]; ok {
		if bytes.Equal(existing, canonical) {
			return nil, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting keygen confirmation from party %d", env.From))
	}
	if s.newShare != nil {
		if err := verifyKeygenConfirmationForPreservedChainCode(s.newShare, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	s.confirmations[env.From] = append([]byte(nil), canonical...)
	if s.newShare != nil && len(s.confirmations) == len(s.oldKey.state.parties) {
		return nil, s.finalizeConfirmedShare()
	}
	return nil, nil
}

func (s *RefreshSession) finalizeConfirmedShare() error {
	if s.newShare == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.oldKey.state.party, errors.New("missing pending refresh share"))
	}
	encoded := make([][]byte, len(s.oldKey.state.parties))
	for i, id := range s.oldKey.state.parties {
		confirmation, ok := s.confirmations[id]
		if !ok {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing keygen confirmation from party %d", id))
		}
		encoded[i] = append([]byte(nil), confirmation...)
	}
	if err := verifyKeygenConfirmationSetPreservedChainCode(s.newShare, encoded); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.oldKey.state.party, err)
	}
	s.newShare.state.keygenConfirmations = wireutil.CloneByteSlices(encoded)
	if err := s.newShare.ValidateWithLimits(s.limits); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.oldKey.state.party, err)
	}
	s.completed = true
	clear(s.newPaillierPriv)
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	confirmationSetHash := keygenConfirmationSetHash(s.newShare.state.keygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "refresh complete",
		"party_id", s.oldKey.state.party,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}
