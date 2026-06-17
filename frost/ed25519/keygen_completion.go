package ed25519

import (
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func (s *KeygenSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.pending != nil {
		if len(s.confirmations) == len(s.cfg.Parties) {
			return nil, s.finalizeConfirmedKeyShare()
		}
		return nil, nil
	}
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) || len(s.chainCodeComms) != len(s.cfg.Parties) {
		return nil, nil
	}
	for dealer, share := range s.shares {
		// Verify f_dealer(self) * B against the dealer's public polynomial commitments.
		if err := edcurve.VerifyScalarShare(s.commits[dealer], s.cfg.Self, share); err != nil {
			s.log.Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", dealer,
			)
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: frostKeygenBlame(s.cfg, dealer, s.commits[dealer]),
				Err:   err,
			}
		}
	}
	secret := fed.NewScalar()
	for _, dealer := range s.cfg.Parties {
		secret.Add(secret, s.shares[dealer])
	}
	secretScalar, err := newEdSecretScalar(secret.Bytes())
	if err != nil {
		return nil, err
	}
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*fed.Point, 0, len(s.cfg.Parties))
		for _, dealer := range s.cfg.Parties {
			p, err := edcurve.PointFromBytesAllowIdentity(s.commits[dealer][degree])
			if err != nil {
				return nil, err
			}
			points = append(points, p)
		}
		// Summing same-degree commitments yields the public polynomial for the group secret.
		groupCommitments[degree] = edcurve.AddPoints(points...).Bytes()
	}
	if _, err := edcurve.PointFromBytes(groupCommitments[0]); err != nil {
		return nil, fmt.Errorf("invalid group public key: %w", err)
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := edcurve.EvalCommitments(groupCommitments, id)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub})
	}
	// Chain code commitment binds the aggregate of all round-1 chain code
	// commitments into the transcript. Individual chain codes are revealed
	// and verified in round 2 confirmations.
	chainCodeCommitAggregate, err := bip32util.AggregateChainCode(s.cfg.Parties, s.chainCodeComms)
	if err != nil {
		return nil, err
	}
	keygenTranscriptHash := frostKeygenTranscriptHash(s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties, chainCodeCommitAggregate, s.planHash, s.commits, groupCommitments, verificationShares)
	share := &KeyShare{state: &keyShareState{
		version:              tss.Version,
		party:                s.cfg.Self,
		threshold:            s.cfg.Threshold,
		parties:              s.cfg.Parties.Clone(),
		publicKey:            append([]byte(nil), groupCommitments[0]...),
		chainCode:            append([]byte(nil), s.chainCodes[s.cfg.Self]...),
		secret:               secretScalar,
		groupCommitments:     groupCommitments,
		verificationShares:   verificationShares,
		keygenSessionID:      s.cfg.SessionID,
		keygenTranscriptHash: keygenTranscriptHash,
		planHash:             append([]byte(nil), s.planHash...),
	}}
	if err := share.validateConsistencyWithoutConfirmations(); err != nil {
		return nil, err
	}
	confirmation, err := share.KeygenConfirmation()
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.confirmations[s.cfg.Self] = append([]byte(nil), encodedConfirmation...)
	s.pending = share
	confirmationEnv, err := envelope(s.cfg, keygenConfirmationRound, s.cfg.Self, 0, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	s.log.Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if len(s.confirmations) == len(s.cfg.Parties) {
		if err := s.finalizeConfirmedKeyShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func validateCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for i, commitment := range commitments {
		if i == 0 {
			if _, err := edcurve.PointFromBytes(commitment); err != nil {
				return err
			}
			continue
		}
		if _, err := edcurve.PointFromBytesAllowIdentity(commitment); err != nil {
			return err
		}
	}
	return nil
}
