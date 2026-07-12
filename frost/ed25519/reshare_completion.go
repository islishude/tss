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
	newShare           *KeyShare
	dealerOnlyComplete bool
	confirmations      map[tss.PartyID]*KeygenConfirmation
	confirmationEnv    tss.Envelope
	finalComplete      bool
	committed          bool
}

func (p *preparedReshareCompletion) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.newShare != nil {
		p.newShare.Destroy()
		p.newShare = nil
	}
	for id, confirmation := range p.confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(p.confirmations, id)
	}
	clear(p.confirmationEnv.Payload)
}

func (s *ReshareSession) maybePrepareReshareCompletion() (*preparedReshareCompletion, bool, error) {
	if s.completed {
		return nil, false, nil
	}
	// Dealer-only (not in new set): only need commitments from all old parties.
	// Shares are sent to newParties, not to removed dealers, so we don't wait
	// for shares here.
	if !s.isRecipient() {
		if len(s.commits) != len(s.oldParties) {
			return nil, false, nil
		}
		newCommitments, err := s.aggregateCommitments()
		if err != nil {
			return nil, false, err
		}
		if !newCommitments.PublicKey().Equal(s.oldPublicKey) {
			return nil, false, errors.New("reshared group public key does not match original")
		}
		return &preparedReshareCompletion{dealerOnlyComplete: true}, true, nil
	}
	// Recipient: wait for commitments and shares from all old parties.
	if len(s.commits) != len(s.oldParties) || len(s.shares) != len(s.oldParties) {
		return nil, false, nil
	}
	// Verify each dealer's share against their commitments at the local party's ID.
	for dealer, share := range s.shares {
		edShare, err := edScalarFromSecret(share)
		if err != nil {
			return nil, false, err
		}
		verifyErr := s.commits[dealer].VerifyShare(s.selfID, edShare)
		edShare.Set(fed.NewScalar())
		if verifyErr != nil {
			return nil, false, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: reshareStartRound,
				Party: dealer,
				Blame: frostReshareBlame(s.cfg, dealer, s.commits[dealer].BytesList()),
				Err:   verifyErr,
			}
		}
	}

	newSecret := fed.NewScalar()
	publicKey := s.oldPublicKey.Clone()
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
	newSecretScalar, err := newEdSecretScalar(newSecret.Bytes())
	newSecret.Set(fed.NewScalar())
	if err != nil {
		return nil, false, err
	}

	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		newSecretScalar.Destroy()
		return nil, false, err
	}

	// Verify group public key is preserved.
	if err := newCommitments.Validate(); err != nil {
		newSecretScalar.Destroy()
		return nil, false, fmt.Errorf("invalid reshared group public key: %w", err)
	}
	if !newCommitments.PublicKey().Equal(publicKey) {
		newSecretScalar.Destroy()
		return nil, false, errors.New("reshared group public key does not match original")
	}
	publicKey = newCommitments.PublicKey()

	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := newCommitments.Eval(id)
		if err != nil {
			newSecretScalar.Destroy()
			return nil, false, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub.Clone()})
		partyData[id] = keySharePartyData{VerificationShare: pub}
	}
	chainCode := append([]byte(nil), s.chainCode...)
	dealerCommitments := make(map[tss.PartyID][][]byte, len(s.commits))
	for dealer, commitments := range s.commits {
		dealerCommitments[dealer] = commitments.BytesList()
	}
	reshareTranscriptHash := frostReshareTranscriptHash(s.cfg.SessionID, s.oldParties, s.newParties, s.newThreshold, s.oldPublicKey.Bytes(), chainCode, s.planHash, s.isRefresh(), dealerCommitments, newCommitments.BytesList(), verificationShares)
	newShare := &KeyShare{state: &keyShareState{
		Party:                s.selfID,
		Threshold:            s.newThreshold,
		Parties:              s.newParties.Clone(),
		PublicKey:            publicKey.Clone(),
		ChainCode:            chainCode,
		Secret:               newSecretScalar,
		GroupCommitments:     newCommitments.Clone(),
		PartyData:            partyData,
		KeygenSessionID:      s.cfg.SessionID,
		KeygenTranscriptHash: reshareTranscriptHash,
		PlanHash:             append([]byte(nil), s.planHash...),
		ConfirmationMode:     keyShareConfirmationModeLifecycleAggregate,
	}}
	if err := newShare.validateConsistencyWithoutConfirmations(); err != nil {
		newShare.Destroy()
		return nil, false, err
	}
	confirmation, err := newShare.keygenConfirmationReferenceUnchecked()
	if err != nil {
		newShare.Destroy()
		return nil, false, err
	}
	encoded, err := confirmation.MarshalBinary()
	if err != nil {
		clear(confirmation.ChainCode)
		newShare.Destroy()
		return nil, false, err
	}
	confirmationEnv, err := newEnvelope(s.cfg, reshareConfirmationRound, s.selfID, tss.BroadcastPartyId, payloadReshareConfirmation, encoded)
	clear(encoded)
	if err != nil {
		clear(confirmation.ChainCode)
		newShare.Destroy()
		return nil, false, err
	}
	confirmations := make(map[tss.PartyID]*KeygenConfirmation, len(s.pendingConfirmations)+1)
	confirmations[s.selfID] = confirmation
	for id, pendingConfirmation := range s.pendingConfirmations {
		if id == s.selfID {
			continue
		}
		if err := verifyReshareConfirmationForShare(newShare, pendingConfirmation); err != nil {
			for _, staged := range confirmations {
				clear(staged.ChainCode)
			}
			clear(confirmationEnv.Payload)
			newShare.Destroy()
			return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, id, err)
		}
		confirmations[id] = pendingConfirmation.Clone()
	}
	finalComplete := len(confirmations) == len(s.newParties)
	if finalComplete {
		ordered, err := orderedReshareConfirmations(s.newParties, confirmations)
		if err != nil {
			newShare.Destroy()
			return nil, false, err
		}
		if err := applyKeygenConfirmationSet(newShare, ordered); err != nil {
			newShare.Destroy()
			return nil, false, err
		}
		if err := newShare.ValidateConsistency(); err != nil {
			newShare.Destroy()
			return nil, false, err
		}
	}
	return &preparedReshareCompletion{
		newShare:        newShare,
		confirmations:   confirmations,
		confirmationEnv: confirmationEnv,
		finalComplete:   finalComplete,
	}, true, nil
}

func (s *ReshareSession) commitReshareCompletion(p *preparedReshareCompletion) []tss.Envelope {
	if p == nil {
		return nil
	}
	if p.dealerOnlyComplete {
		s.completed = true
		s.clearSensitive()
		s.log.Info(s.cfg.Ctx(), "reshare complete",
			"party_id", s.selfID,
			"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		)
		p.committed = true
		return nil
	}
	s.confirmations = p.confirmations
	s.clearPendingConfirmations()
	s.pendingConfirmations = nil
	if p.finalComplete {
		s.newShare = p.newShare
		s.completed = true
	} else {
		s.pendingShare = p.newShare
	}
	s.clearSensitive()
	s.log.Info(s.cfg.Ctx(), "reshare local material complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	p.committed = true
	return []tss.Envelope{p.confirmationEnv}
}

func verifyReshareConfirmationForShare(share *KeyShare, confirmation *KeygenConfirmation) error {
	if share == nil || share.state == nil {
		return errors.New("nil pending reshare key share")
	}
	if confirmation == nil {
		return errors.New("nil reshare confirmation")
	}
	if err := confirmation.Validate(); err != nil {
		return err
	}
	reference, err := share.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return err
	}
	if err := compareKeygenConfirmationBindingFields(reference, confirmation); err != nil {
		return err
	}
	if !bytes.Equal(confirmation.ChainCode, share.state.ChainCode) {
		return fmt.Errorf("reshare confirmation chain code mismatch from party %d", confirmation.Sender)
	}
	return nil
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
	if s.pendingShare == nil || len(s.confirmations) != len(s.newParties) {
		return nil
	}
	ordered, err := orderedReshareConfirmations(s.newParties, s.confirmations)
	if err != nil {
		return err
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
