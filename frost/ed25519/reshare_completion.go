package ed25519

import (
	"bytes"
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
		if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
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
		if err := edcurve.VerifyScalarShare(s.commits[dealer], s.selfID, share); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: frostReshareBlame(s.cfg, dealer, s.commits[dealer]),
				Err:   err,
			}
		}
	}

	newSecret := fed.NewScalar()
	publicKey := append([]byte(nil), s.oldPublicKey...)
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
	if _, err := edcurve.PointFromBytes(newCommitments[0]); err != nil {
		return fmt.Errorf("invalid reshared group public key: %w", err)
	}
	if !bytes.Equal(newCommitments[0], publicKey) {
		return errors.New("reshared group public key does not match original")
	}
	publicKey = append([]byte(nil), newCommitments[0]...)

	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := edcurve.EvalCommitments(newCommitments, id)
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub})
	}
	chainCode := append([]byte(nil), s.chainCode...)
	reshareTranscriptHash := frostReshareTranscriptHash(s.cfg.SessionID, s.oldParties, s.newParties, s.newThreshold, s.oldPublicKey, chainCode, s.planHash, s.refreshMode, s.commits, newCommitments, verificationShares)
	newShare := &KeyShare{state: &keyShareState{
		version:              tss.Version,
		party:                s.selfID,
		threshold:            s.newThreshold,
		parties:              s.newParties.Clone(),
		publicKey:            append([]byte(nil), publicKey...),
		chainCode:            chainCode,
		secret:               newSecretScalar,
		groupCommitments:     newCommitments,
		verificationShares:   verificationShares,
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

func (s *ReshareSession) aggregateCommitments() ([][]byte, error) {
	newCommitments := make([][]byte, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*fed.Point, 0, len(s.oldParties)+1)
		for _, dealer := range s.oldParties {
			p, err := edcurve.PointFromBytesAllowIdentity(s.commits[dealer][degree])
			if err != nil {
				return nil, err
			}
			points = append(points, p)
		}
		if s.refreshMode && degree < len(s.oldKey.state.groupCommitments) {
			oldCommitment, err := edcurve.PointFromBytesAllowIdentity(s.oldKey.state.groupCommitments[degree])
			if err != nil {
				return nil, err
			}
			points = append(points, oldCommitment)
		}
		newCommitments[degree] = edcurve.AddPoints(points...).Bytes()
	}
	if _, err := edcurve.PointFromBytes(newCommitments[0]); err != nil {
		return nil, fmt.Errorf("invalid reshared group public key: %w", err)
	}
	return newCommitments, nil
}

func validateReshareCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for _, commitment := range commitments {
		if _, err := edcurve.PointFromBytesAllowIdentity(commitment); err != nil {
			return err
		}
	}
	return nil
}
