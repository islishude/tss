package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
)

func (s *ReshareSession) handleReshareConfirmationInbound(in tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	env := in.Envelope()
	if env.Round != reshareConfirmationRound || env.To != tss.BroadcastPartyId {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare confirmation in wrong round or delivery mode"))
	}
	if s.isReceiver && s.auxInfo == nil && s.newShare == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare confirmation arrived before the local Figure 7 phase"))
	}
	confirmation := new(KeygenConfirmation)
	if err := confirmation.UnmarshalBinaryWithLimits(env.Payload, s.limits); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	owned := true
	defer func() {
		if owned {
			clear(confirmation.ChainCode)
		}
	}()
	if confirmation.Sender != env.From {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("reshare confirmation sender mismatch"))
	}
	canonical, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical reshare confirmation"))
	}
	if err := requirePlanHash("reshare confirmation", confirmation.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if err := s.verifyReshareConfirmationPublicBinding(confirmation); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	data, ok := s.newPartyData[env.From]
	if !ok {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("party %d is not a target reshare party", env.From))
	}
	if data.confirmation != nil {
		existing, marshalErr := data.confirmation.MarshalBinaryWithLimits(s.limits)
		if marshalErr == nil && bytes.Equal(existing, canonical) {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, tss.ErrDuplicateMessage)
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting reshare confirmation from party %d", env.From))
	}
	if s.newShare != nil {
		if err := verifyKeygenConfirmationForPreservedChainCode(s.newShare, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	confirmations := s.reshareConfirmationCandidates(env.From, confirmation)
	defer destroyPaperConfirmationMap(confirmations)
	var final *preparedPaperFinalKeyShare
	if s.newShare != nil && len(confirmations) == len(s.newParties) {
		final, err = s.buildReshareFinalKeyShare(s.newShare, confirmations)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		defer final.destroy()
	}
	if err := s.validateInbound(in, s.newParties); err != nil {
		return nil, err
	}
	data.confirmation = confirmation
	s.accepted[key] = struct{}{}
	owned = false
	if final != nil {
		if err := s.commitReshareFinalKeyShare(final); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, s.selfID, err)
		}
		return nil, nil
	}
	if !s.isReceiver {
		if err := s.tryCompleteDealerOnly(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (s *ReshareSession) verifyReshareConfirmationPublicBinding(confirmation *KeygenConfirmation) error {
	if confirmation == nil {
		return errors.New("nil reshare confirmation")
	}
	if !s.newParties.Contains(confirmation.Sender) || confirmation.SessionID != s.cfg.SessionID ||
		confirmation.Threshold != s.newThreshold || !slices.Equal(confirmation.Parties, s.newParties) ||
		!bytes.Equal(confirmation.PublicKey, s.oldPublicKey) || !bytes.Equal(confirmation.ChainCode, s.oldChainCode) ||
		!bytes.Equal(confirmation.PlanHash, s.planHash) {
		return errors.New("reshare confirmation public binding mismatch")
	}
	return nil
}

func (s *ReshareSession) finalizeConfirmedShare() error {
	if s.newShare == nil {
		return tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, s.selfID, errors.New("missing pending reshare share"))
	}
	confirmations := s.reshareConfirmationCandidates(tss.BroadcastPartyId, nil)
	defer destroyPaperConfirmationMap(confirmations)
	prepared, err := s.buildReshareFinalKeyShare(s.newShare, confirmations)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, s.selfID, err)
	}
	defer prepared.destroy()
	if err := s.commitReshareFinalKeyShare(prepared); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareConfirmationRound, s.selfID, err)
	}
	return nil
}
