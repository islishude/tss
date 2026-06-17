package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
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
	pd, err := s.partyEntry(env.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if pd.confirmation != nil {
		existing, err := pd.confirmation.MarshalBinary()
		if err == nil && bytes.Equal(existing, canonical) {
			return nil, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting keygen confirmation from party %d", env.From))
	}
	if s.newShare != nil {
		if err := verifyKeygenConfirmationForPreservedChainCode(s.newShare, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	pd.confirmation = confirmation
	if s.newShare != nil && s.allRefreshConfirmationsReceived() {
		return nil, s.finalizeConfirmedShare()
	}
	return nil, nil
}

func (s *RefreshSession) finalizeConfirmedShare() error {
	if s.newShare == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.oldKey.state.party, errors.New("missing pending refresh share"))
	}
	// Collect parsed confirmations in party order (no re-unmarshal needed).
	confirmations := make([]*KeygenConfirmation, len(s.oldKey.state.parties))
	for i, id := range s.oldKey.state.parties {
		c := s.partyData[id].confirmation
		if c == nil {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing keygen confirmation from party %d", id))
		}
		confirmations[i] = c
	}
	if err := verifyFinalizedKeygenConfirmationSet(s.newShare, confirmations); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.oldKey.state.party, err)
	}
	// Verify preserved chain code on each confirmation.
	for _, c := range confirmations {
		if !bytes.Equal(c.ChainCode, s.newShare.state.chainCode) {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, c.Sender, fmt.Errorf("keygen confirmation chain code mismatch from party %d", c.Sender))
		}
	}
	s.newShare.state.keygenConfirmations = tss.CloneSlices(confirmations)
	if err := s.newShare.ValidateWithLimits(s.limits); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.oldKey.state.party, err)
	}
	s.completed = true
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
