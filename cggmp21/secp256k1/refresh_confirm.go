package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/planvalidation"
)

func (s *RefreshSession) handlePaperRefreshConfirmation(in tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	env := in.Envelope()
	if env.Round != refreshConfirmationRound || env.To != tss.BroadcastPartyId {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh confirmation in wrong round or delivery mode"))
	}
	if s.auxInfo == nil && s.newShare == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh confirmation arrived before Figure 7 started"))
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
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("refresh confirmation sender mismatch"))
	}
	canonical, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical refresh confirmation"))
	}
	if err := planvalidation.RequireHash("refresh confirmation", confirmation.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if err := validatePaperRefreshConfirmationPublicBinding(s, confirmation); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	pd, err := s.partyEntry(env.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if pd.confirmation != nil {
		existing, marshalErr := pd.confirmation.MarshalBinaryWithLimits(s.limits)
		if marshalErr == nil && bytes.Equal(existing, canonical) {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, tss.ErrDuplicateMessage)
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting refresh confirmation from party %d", env.From))
	}
	if s.newShare != nil {
		if err := verifyKeygenConfirmationForPreservedChainCode(s.newShare, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	candidates := s.refreshConfirmationCandidates(env.From, confirmation)
	defer destroyPaperConfirmationMap(candidates)
	var final *preparedPaperFinalKeyShare
	if s.newShare != nil && len(candidates) == len(s.cfg.Parties) {
		final, err = s.buildPaperRefreshFinalKeyShare(s.newShare, candidates)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		defer final.destroy()
	}
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	pd.confirmation = confirmation
	s.accepted[key] = struct{}{}
	owned = false
	if final != nil {
		if err := s.commitPaperRefreshFinalKeyShare(final); err != nil {
			return nil, err
		}
	}
	return nil, nil
}
