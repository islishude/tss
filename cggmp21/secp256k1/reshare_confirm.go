package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire/wireutil"
)

func (s *ReshareSession) handleReshareConfirmation(env tss.Envelope) ([]tss.Envelope, error) {
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
	if err := requirePlanHash("reshare confirmation", confirmation.PlanHash, s.planHash); err != nil {
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
	return s.tryComplete()
}

func (s *ReshareSession) verifyReshareConfirmationForPublicTranscript(c *KeygenConfirmation, newCommitments [][]byte) error {
	if c == nil {
		return errors.New("nil reshare confirmation")
	}
	if !tss.ContainsParty(s.newParties, c.Sender) {
		return fmt.Errorf("reshare confirmation from unknown new party %d", c.Sender)
	}
	if c.SessionID != s.cfg.SessionID {
		return fmt.Errorf("reshare confirmation session mismatch from party %d", c.Sender)
	}
	if c.Threshold != s.newThreshold {
		return fmt.Errorf("reshare confirmation threshold mismatch from party %d: got %d, want %d", c.Sender, c.Threshold, s.newThreshold)
	}
	if !slices.Equal(c.Parties, s.newParties) {
		return fmt.Errorf("reshare confirmation party set mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.PublicKey, s.oldPublicKey) {
		return fmt.Errorf("reshare confirmation public key mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.TranscriptHash, s.reshareTranscriptHash(newCommitments)) {
		return fmt.Errorf("reshare confirmation transcript mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.PlanHash, s.planHash) {
		return fmt.Errorf("reshare confirmation from party %d: %w", c.Sender, errPlanHashMismatch)
	}
	if !bytes.Equal(c.CommitmentsHash, keygenCommitmentsHash(newCommitments)) {
		return fmt.Errorf("reshare confirmation commitments mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.ChainCode, s.oldChainCode) {
		return fmt.Errorf("reshare confirmation chain code mismatch from party %d", c.Sender)
	}
	return nil
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
	if err := verifyKeygenConfirmationSetPreservedChainCode(s.newShare, encoded); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, err)
	}
	s.newShare.state.keygenConfirmations = wireutil.CloneByteSlices(encoded)
	if err := s.newShare.ValidateWithLimits(s.limits); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, err)
	}
	s.completed = true
	clear(s.newPaillierPriv)
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	confirmationSetHash := keygenConfirmationSetHash(s.newShare.state.keygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}
