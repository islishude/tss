package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/planvalidation"
)

func (s *ChildDerivationSession) handleChildConfirmationLocked(in tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	env := in.Envelope()
	if env.Round != childConfirmationRound || env.To != tss.BroadcastPartyId {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("child confirmation in wrong round or delivery mode"))
	}
	if s.auxInfo == nil && s.pending == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("child confirmation arrived before Figure 7 started"))
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
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("child confirmation sender mismatch"))
	}
	canonical, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical child confirmation"))
	}
	if err := planvalidation.RequireHash("child confirmation", confirmation.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if err := s.validateChildConfirmationPublicBinding(confirmation); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if existing := s.confirmations[env.From]; existing != nil {
		existingRaw, marshalErr := existing.MarshalBinaryWithLimits(s.limits)
		if marshalErr == nil && bytes.Equal(existingRaw, canonical) {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, tss.ErrDuplicateMessage)
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting child confirmation from party %d", env.From))
	}
	if s.pending != nil {
		if err := verifyKeygenConfirmationForPreservedChainCode(s.pending, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	candidates := s.childConfirmationCandidates(env.From, confirmation)
	defer destroyPaperConfirmationMap(candidates)
	var final *KeyShare
	if s.pending != nil && len(candidates) == len(s.cfg.Parties) {
		final, err = s.buildChildFinalKeyShare(s.pending, candidates)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		defer final.Destroy()
	}
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	s.confirmations[env.From] = confirmation
	s.accepted[key] = struct{}{}
	owned = false
	if final != nil {
		if err := s.persistChildGenerationLocked(final); err != nil {
			return nil, s.abortRunLocked(err)
		}
	}
	return nil, nil
}

func (s *ChildDerivationSession) validateChildConfirmationPublicBinding(confirmation *KeygenConfirmation) error {
	if confirmation == nil {
		return errors.New("nil child confirmation")
	}
	if confirmation.SessionID != s.plan.SessionID ||
		confirmation.Threshold != s.plan.Threshold ||
		!slices.Equal(confirmation.Parties, s.plan.Parties) ||
		!bytes.Equal(confirmation.PublicKey, s.plan.Derivation.ChildPublicKey) ||
		!bytes.Equal(confirmation.ChainCode, s.plan.Derivation.ChildChainCode) {
		return errors.New("child confirmation public binding mismatch")
	}
	return nil
}
