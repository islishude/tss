package ed25519

import (
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func (s *ReshareSession) tryComplete() error {
	if s.completed {
		return nil
	}
	// Dealer-only (not in new set): only need commitments from all old parties.
	// Shares are sent to newParties, not to removed dealers, so we don't wait
	// for shares here.
	if !s.isRecipient {
		if len(s.commits) != len(s.oldParties) {
			return nil
		}
		newCommitments, err := s.aggregateCommitments()
		if err != nil {
			return err
		}
		if !newCommitments.PublicKey().Equal(s.oldPublicKey) {
			return errors.New("reshared group public key does not match original")
		}
		s.completed = true
		s.clearSensitive()
		return nil
	}
	// Recipient: wait for commitments and shares from all old parties.
	if len(s.commits) != len(s.oldParties) || len(s.shares) != len(s.oldParties) {
		return nil
	}
	// Verify each dealer's share against their commitments at the local party's ID.
	for dealer, share := range s.shares {
		if err := s.commits[dealer].VerifyShare(s.selfID, share); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: frostReshareBlame(s.cfg, dealer, s.commits[dealer].BytesList()),
				Err:   err,
			}
		}
	}

	newSecret := fed.NewScalar()
	publicKey := s.oldPublicKey.Clone()
	if s.refreshMode {
		// Refresh: new_secret = old_secret + Σ f_i(self) mod L.
		// New commitments = old_commitments + Σ dealer_commitments.
		oldSecret, err := s.oldKey.secretScalar()
		if err != nil {
			return err
		}
		newSecret.Add(newSecret, oldSecret)
		for _, dealer := range s.oldParties {
			newSecret.Add(newSecret, s.shares[dealer])
		}
	} else {
		// True reshare: new_secret = Σ g_i(self) mod L.
		for _, dealer := range s.oldParties {
			newSecret.Add(newSecret, s.shares[dealer])
		}
	}
	newSecretScalar, err := newEdSecretScalar(newSecret.Bytes())
	if err != nil {
		return err
	}

	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		return err
	}

	// Verify group public key is preserved.
	if err := newCommitments.Validate(); err != nil {
		return fmt.Errorf("invalid reshared group public key: %w", err)
	}
	if !newCommitments.PublicKey().Equal(publicKey) {
		return errors.New("reshared group public key does not match original")
	}
	publicKey = newCommitments.PublicKey()

	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := newCommitments.Eval(id)
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub.Clone()})
		partyData[id] = keySharePartyData{verificationShare: pub}
	}
	chainCode := append([]byte(nil), s.chainCode...)
	dealerCommitments := make(map[tss.PartyID][][]byte, len(s.commits))
	for dealer, commitments := range s.commits {
		dealerCommitments[dealer] = commitments.BytesList()
	}
	reshareTranscriptHash := frostReshareTranscriptHash(s.cfg.SessionID, s.oldParties, s.newParties, s.newThreshold, s.oldPublicKey.Bytes(), chainCode, s.planHash, s.refreshMode, dealerCommitments, newCommitments.BytesList(), verificationShares)
	newShare := &KeyShare{state: &keyShareState{
		party:                s.selfID,
		threshold:            s.newThreshold,
		parties:              s.newParties.Clone(),
		publicKey:            publicKey.Clone(),
		chainCode:            chainCode,
		secret:               newSecretScalar,
		groupCommitments:     newCommitments.Clone(),
		partyData:            partyData,
		keygenSessionID:      s.cfg.SessionID,
		keygenTranscriptHash: reshareTranscriptHash,
		planHash:             append([]byte(nil), s.planHash...),
	}}
	if err := newShare.ValidateConsistency(); err != nil {
		newShare.Destroy()
		return err
	}
	s.newShare = newShare
	s.completed = true
	s.clearSensitive()
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
		if s.refreshMode && degree < s.oldKey.state.groupCommitments.Len() {
			oldCommitment, err := s.oldKey.state.groupCommitments.PointAtAllowIdentity(degree)
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
