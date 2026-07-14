package ed25519

import (
	"bytes"
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func (s *ReshareSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	prepared, ok, err := s.maybePrepareReshareCompletion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer prepared.destroy()
	out := s.commitReshareCompletion(prepared)
	return out, nil
}

type preparedReshareCompletion struct {
	newShare            *KeyShare
	confirmationBinding *reshareConfirmationBinding
	confirmations       map[tss.PartyID]*KeygenConfirmation
	confirmationEnv     tss.Envelope
	finalComplete       bool
	committed           bool
}

// reshareConfirmationBinding is the public, sender-independent statement that
// every target key holder must confirm. It is derived entirely from the plan
// and the complete set of old-dealer commitments, so dealer-only roles can
// verify the same statement without receiving a secret share.
type reshareConfirmationBinding struct {
	sessionID       tss.SessionID
	threshold       int
	parties         tss.PartySet
	publicKey       publicKeyPoint
	transcriptHash  []byte
	commitmentsHash []byte
	chainCode       []byte
	planHash        []byte
}

func (b *reshareConfirmationBinding) confirmation(sender tss.PartyID) *KeygenConfirmation {
	if b == nil {
		return nil
	}
	return &KeygenConfirmation{
		SessionID:       b.sessionID,
		Sender:          sender,
		Threshold:       b.threshold,
		Parties:         b.parties.Clone(),
		PublicKey:       b.publicKey.Clone(),
		TranscriptHash:  bytes.Clone(b.transcriptHash),
		CommitmentsHash: bytes.Clone(b.commitmentsHash),
		ChainCode:       bytes.Clone(b.chainCode),
		PlanHash:        bytes.Clone(b.planHash),
	}
}

func (b *reshareConfirmationBinding) verify(confirmation *KeygenConfirmation) error {
	if b == nil {
		return errors.New("nil reshare confirmation binding")
	}
	if confirmation == nil {
		return errors.New("nil reshare confirmation")
	}
	if err := confirmation.Validate(); err != nil {
		return err
	}
	reference := b.confirmation(confirmation.Sender)
	if err := compareKeygenConfirmationBindingFields(reference, confirmation); err != nil {
		clear(reference.ChainCode)
		return err
	}
	clear(reference.ChainCode)
	if !bytes.Equal(confirmation.ChainCode, b.chainCode) {
		return fmt.Errorf("reshare confirmation chain code mismatch from party %d", confirmation.Sender)
	}
	return nil
}

func (b *reshareConfirmationBinding) destroy() {
	if b == nil {
		return
	}
	clear(b.transcriptHash)
	clear(b.commitmentsHash)
	clear(b.chainCode)
	clear(b.planHash)
	b.transcriptHash = nil
	b.commitmentsHash = nil
	b.chainCode = nil
	b.planHash = nil
}

func (p *preparedReshareCompletion) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.newShare != nil {
		p.newShare.Destroy()
		p.newShare = nil
	}
	if p.confirmationBinding != nil {
		p.confirmationBinding.destroy()
		p.confirmationBinding = nil
	}
	clearReshareConfirmationMap(p.confirmations)
	clear(p.confirmationEnv.Payload)
}

func (s *ReshareSession) maybePrepareReshareCompletion() (*preparedReshareCompletion, bool, error) {
	if s.completed {
		return nil, false, nil
	}
	if len(s.commits) != len(s.oldParties) {
		return nil, false, nil
	}
	// Recipients need every secret contribution before they can stage a share.
	// Dealer-only roles need only the public commitment set to derive the exact
	// confirmation statement expected from target key holders.
	if s.isRecipient() && len(s.shares) != len(s.oldParties) {
		return nil, false, nil
	}

	newCommitments, binding, partyData, err := s.prepareResharePublicBinding()
	if err != nil {
		return nil, false, err
	}
	prepared := &preparedReshareCompletion{
		confirmationBinding: binding,
		confirmations:       make(map[tss.PartyID]*KeygenConfirmation, len(s.pendingConfirmations)+1),
	}
	releasePrepared := true
	defer func() {
		if releasePrepared {
			prepared.destroy()
		}
	}()

	if !s.isRecipient() {
		if err := s.copyAndVerifyPendingReshareConfirmations(prepared); err != nil {
			return nil, false, err
		}
		prepared.finalComplete = len(prepared.confirmations) == len(s.newParties)
		if prepared.finalComplete {
			if _, err := orderedReshareConfirmations(s.newParties, prepared.confirmations); err != nil {
				return nil, false, err
			}
		}
		releasePrepared = false
		return prepared, true, nil
	}

	if err := s.verifyReshareDealerShares(); err != nil {
		return nil, false, err
	}

	newSecret := fed.NewScalar()
	if s.isRefresh() {
		// Refresh: new_secret = old_secret + Σ f_i(self) mod L.
		// New commitments = old_commitments + Σ dealer_commitments.
		oldSecret, err := s.oldKey.secretScalar()
		if err != nil {
			newSecret.Set(fed.NewScalar())
			return nil, false, err
		}
		newSecret.Add(newSecret, oldSecret)
		oldSecret.Set(fed.NewScalar())
		for _, dealer := range s.oldParties {
			share, err := edScalarFromSecret(s.shares[dealer])
			if err != nil {
				newSecret.Set(fed.NewScalar())
				return nil, false, err
			}
			newSecret.Add(newSecret, share)
			share.Set(fed.NewScalar())
		}
	} else {
		// True reshare: new_secret = Σ g_i(self) mod L.
		for _, dealer := range s.oldParties {
			share, err := edScalarFromSecret(s.shares[dealer])
			if err != nil {
				newSecret.Set(fed.NewScalar())
				return nil, false, err
			}
			newSecret.Add(newSecret, share)
			share.Set(fed.NewScalar())
		}
	}
	newSecretScalar, err := newEdSecretScalarFromFed(newSecret)
	newSecret.Set(fed.NewScalar())
	if err != nil {
		return nil, false, err
	}

	publicKey := newCommitments.PublicKey()
	newShare := &KeyShare{state: &keyShareState{
		Party:                s.selfID,
		Threshold:            s.newThreshold,
		Parties:              s.newParties.Clone(),
		PublicKey:            publicKey.Clone(),
		ChainCode:            bytes.Clone(binding.chainCode),
		Secret:               newSecretScalar,
		GroupCommitments:     newCommitments.Clone(),
		PartyData:            partyData,
		KeygenSessionID:      s.cfg.SessionID,
		KeygenTranscriptHash: bytes.Clone(binding.transcriptHash),
		PlanHash:             append([]byte(nil), s.planHash...),
		ConfirmationMode:     keyShareConfirmationModeLifecycleAggregate,
	}}
	prepared.newShare = newShare
	if err := newShare.validateConsistencyWithoutConfirmations(); err != nil {
		return nil, false, err
	}
	confirmation := binding.confirmation(s.selfID)
	encoded, err := confirmation.MarshalBinary()
	if err != nil {
		clear(confirmation.ChainCode)
		return nil, false, err
	}
	confirmationEnv, err := newEnvelope(s.cfg, reshareConfirmationRound, s.selfID, tss.BroadcastPartyId, payloadReshareConfirmation, encoded)
	clear(encoded)
	if err != nil {
		clear(confirmation.ChainCode)
		return nil, false, err
	}
	prepared.confirmationEnv = confirmationEnv
	prepared.confirmations[s.selfID] = confirmation
	if err := s.copyAndVerifyPendingReshareConfirmations(prepared); err != nil {
		return nil, false, err
	}
	prepared.finalComplete = len(prepared.confirmations) == len(s.newParties)
	if prepared.finalComplete {
		ordered, err := orderedReshareConfirmations(s.newParties, prepared.confirmations)
		if err != nil {
			return nil, false, err
		}
		if err := applyKeygenConfirmationSet(newShare, ordered); err != nil {
			return nil, false, err
		}
		if err := newShare.ValidateConsistency(); err != nil {
			return nil, false, err
		}
	}
	releasePrepared = false
	return prepared, true, nil
}

// verifyReshareDealerShares follows the canonical old-party order so every
// receiver attributes the same first invalid share when several dealers fail.
func (s *ReshareSession) verifyReshareDealerShares() error {
	for _, dealer := range s.oldParties {
		share, ok := s.shares[dealer]
		if !ok || share == nil {
			return fmt.Errorf("missing reshare share from dealer %d", dealer)
		}
		commitments, ok := s.commits[dealer]
		if !ok {
			return fmt.Errorf("missing reshare commitments from dealer %d", dealer)
		}
		edShare, err := edScalarFromSecret(share)
		if err != nil {
			return err
		}
		verifyErr := commitments.VerifyShare(s.selfID, edShare)
		edShare.Set(fed.NewScalar())
		if verifyErr != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: reshareStartRound,
				Party: dealer,
				Blame: frostReshareBlame(s.cfg, dealer, commitments.BytesList()),
				Err:   verifyErr,
			}
		}
	}
	return nil
}

func (s *ReshareSession) prepareResharePublicBinding() (groupCommitments, *reshareConfirmationBinding, map[tss.PartyID]keySharePartyData, error) {
	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		return groupCommitments{}, nil, nil, err
	}
	if err := newCommitments.Validate(); err != nil {
		return groupCommitments{}, nil, nil, fmt.Errorf("invalid reshared group public key: %w", err)
	}
	if !newCommitments.PublicKey().Equal(s.oldPublicKey) {
		return groupCommitments{}, nil, nil, errors.New("reshared group public key does not match original")
	}

	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := newCommitments.Eval(id)
		if err != nil {
			return groupCommitments{}, nil, nil, tss.NewProtocolError(
				tss.ErrCodeVerification,
				reshareStartRound,
				tss.BroadcastPartyId,
				fmt.Errorf("invalid aggregate verification share for party %d: %w", id, err),
			)
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub.Clone()})
		partyData[id] = keySharePartyData{VerificationShare: pub}
	}
	dealerCommitments := make(map[tss.PartyID][][]byte, len(s.commits))
	for dealer, commitments := range s.commits {
		dealerCommitments[dealer] = commitments.BytesList()
	}
	transcriptHash := frostReshareTranscriptHash(
		s.cfg.SessionID,
		s.oldParties,
		s.newParties,
		s.newThreshold,
		s.oldPublicKey.Bytes(),
		s.chainCode,
		s.planHash,
		s.isRefresh(),
		dealerCommitments,
		newCommitments.BytesList(),
		verificationShares,
	)
	binding := &reshareConfirmationBinding{
		sessionID:       s.cfg.SessionID,
		threshold:       s.newThreshold,
		parties:         s.newParties.Clone(),
		publicKey:       s.oldPublicKey.Clone(),
		transcriptHash:  transcriptHash,
		commitmentsHash: keygenGroupCommitmentsHash(newCommitments.BytesList()),
		chainCode:       bytes.Clone(s.chainCode),
		planHash:        bytes.Clone(s.planHash),
	}
	return newCommitments, binding, partyData, nil
}

func (s *ReshareSession) copyAndVerifyPendingReshareConfirmations(prepared *preparedReshareCompletion) error {
	for id, pendingConfirmation := range s.pendingConfirmations {
		if prepared.confirmations[id] != nil {
			continue
		}
		if err := prepared.confirmationBinding.verify(pendingConfirmation); err != nil {
			return tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, id, err)
		}
		prepared.confirmations[id] = pendingConfirmation.Clone()
	}
	return nil
}

func (s *ReshareSession) commitReshareCompletion(p *preparedReshareCompletion) []tss.Envelope {
	if p == nil {
		return nil
	}
	s.confirmationBinding = p.confirmationBinding
	s.confirmations = p.confirmations
	s.clearPendingConfirmations()
	s.pendingConfirmations = nil
	if p.finalComplete && s.isRecipient() {
		s.newShare = p.newShare
		s.completed = true
	} else if s.isRecipient() {
		s.pendingShare = p.newShare
	} else if p.finalComplete {
		s.completed = true
	}
	s.clearSensitive()
	message := "reshare confirmation binding ready"
	if s.completed {
		message = "reshare complete"
	} else if s.isRecipient() {
		message = "reshare local material complete"
	}
	s.log.Info(s.cfg.Ctx(), message,
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	p.committed = true
	if !s.isRecipient() {
		return nil
	}
	return []tss.Envelope{p.confirmationEnv}
}

func clearReshareConfirmationMap(confirmations map[tss.PartyID]*KeygenConfirmation) {
	for id, confirmation := range confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(confirmations, id)
	}
}

func (s *ReshareSession) clearReshareConfirmationState() {
	if s == nil {
		return
	}
	s.clearPendingConfirmations()
	clearReshareConfirmationMap(s.confirmations)
	if s.confirmationBinding != nil {
		s.confirmationBinding.destroy()
		s.confirmationBinding = nil
	}
}

func orderedReshareConfirmations(parties tss.PartySet, confirmations map[tss.PartyID]*KeygenConfirmation) ([]*KeygenConfirmation, error) {
	if len(confirmations) != len(parties) {
		return nil, fmt.Errorf("got %d reshare confirmations, want %d", len(confirmations), len(parties))
	}
	ordered := make([]*KeygenConfirmation, 0, len(parties))
	for _, id := range parties {
		confirmation := confirmations[id]
		if confirmation == nil {
			return nil, fmt.Errorf("missing reshare confirmation from party %d", id)
		}
		ordered = append(ordered, confirmation)
	}
	return ordered, nil
}

func (s *ReshareSession) tryFinalizeReshareConfirmations() error {
	if s.confirmationBinding == nil || len(s.confirmations) != len(s.newParties) {
		return nil
	}
	ordered, err := orderedReshareConfirmations(s.newParties, s.confirmations)
	if err != nil {
		return err
	}
	for _, confirmation := range ordered {
		if err := s.confirmationBinding.verify(confirmation); err != nil {
			return err
		}
	}
	if !s.isRecipient() {
		s.completed = true
		s.log.Info(s.cfg.Ctx(), "reshare complete",
			"party_id", s.selfID,
			"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		)
		return nil
	}
	if s.pendingShare == nil {
		return errors.New("missing pending reshare key share")
	}
	candidate := cloneKeyShareValue(s.pendingShare)
	if err := applyKeygenConfirmationSet(candidate, ordered); err != nil {
		candidate.Destroy()
		return err
	}
	if err := candidate.ValidateConsistency(); err != nil {
		candidate.Destroy()
		return err
	}
	s.pendingShare.Destroy()
	s.pendingShare = nil
	s.newShare = candidate
	s.completed = true
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return nil
}

func (s *ReshareSession) aggregateCommitments() (groupCommitments, error) {
	newCommitments := make([]*fed.Point, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*fed.Point, 0, len(s.oldParties)+1)
		for _, dealer := range s.oldParties {
			p, err := s.commits[dealer].PointAt(degree)
			if err != nil {
				return groupCommitments{}, err
			}
			points = append(points, p)
		}
		if s.isRefresh() && degree < s.oldKey.state.GroupCommitments.Len() {
			oldCommitment, err := s.oldKey.state.GroupCommitments.PointAtAllowIdentity(degree)
			if err != nil {
				return groupCommitments{}, err
			}
			points = append(points, oldCommitment)
		}
		newCommitments[degree] = edcurve.AddPoints(points...)
	}
	out, err := newGroupCommitmentsFromPoints(newCommitments, s.newThreshold)
	if err != nil {
		return groupCommitments{}, fmt.Errorf("invalid reshared group public key: %w", err)
	}
	return out, nil
}
