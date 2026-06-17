package ed25519

import (
	"bytes"
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
		if allConfirmationsReceived(s.partyData, s.cfg.Parties) {
			return nil, s.finalizeConfirmedKeyShare()
		}
		return nil, nil
	}
	if !allRound1Received(s.partyData, s.cfg.Parties) {
		return nil, nil
	}
	for _, id := range s.cfg.Parties {
		d := s.partyData[id]
		// Verify f_dealer(self) * B against the dealer's public polynomial commitments.
		if err := edcurve.VerifyScalarShare(d.commitments, s.cfg.Self, d.share); err != nil {
			s.cfg.Logger().Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", id,
			)
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: id,
				Blame: frostKeygenBlame(s.cfg, id, d.commitments),
				Err:   err,
			}
		}
	}
	secret := fed.NewScalar()
	for _, id := range s.cfg.Parties {
		secret.Add(secret, s.partyData[id].share)
	}
	secretScalar, err := newEdSecretScalar(secret.Bytes())
	if err != nil {
		return nil, err
	}
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*fed.Point, 0, len(s.cfg.Parties))
		for _, id := range s.cfg.Parties {
			p, err := edcurve.PointFromBytesAllowIdentity(s.partyData[id].commitments[degree])
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
	chainCodeCommitMap := make(map[tss.PartyID][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		chainCodeCommitMap[id] = s.partyData[id].chainCodeCommit
	}
	chainCodeCommitAggregate, err := bip32util.AggregateChainCode(s.cfg.Parties, chainCodeCommitMap)
	if err != nil {
		return nil, err
	}
	dealerCommits := make(map[tss.PartyID][][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		dealerCommits[id] = s.partyData[id].commitments
	}
	keygenTranscriptHash := frostKeygenTranscriptHash(s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties, chainCodeCommitAggregate, s.planHash, dealerCommits, groupCommitments, verificationShares)
	share := &KeyShare{state: &keyShareState{
		party:                s.cfg.Self,
		threshold:            s.cfg.Threshold,
		parties:              s.cfg.Parties.Clone(),
		publicKey:            append([]byte(nil), groupCommitments[0]...),
		chainCode:            bytes.Clone(s.partyData[s.cfg.Self].chainCode),
		secret:               secretScalar,
		groupCommitments:     groupCommitments,
		verificationShares:   verificationShares,
		keygenSessionID:      s.cfg.SessionID,
		keygenTranscriptHash: keygenTranscriptHash,
		planHash:             bytes.Clone(s.planHash),
	}}
	if err := share.validateConsistencyWithoutConfirmations(); err != nil {
		return nil, err
	}
	confirmation, err := share.NewConfirmation()
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.partyData[s.cfg.Self].confirmation = confirmation
	s.pending = share
	confirmationEnv, err := newEnvelope(s.cfg, keygenConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if allConfirmationsReceived(s.partyData, s.cfg.Parties) {
		if err := s.finalizeConfirmedKeyShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// allRound1Received returns true when every party has submitted commitments,
// shares, and chain code commitments.
func allRound1Received(pd map[tss.PartyID]*keygenPartyData, parties tss.PartySet) bool {
	for _, id := range parties {
		d := pd[id]
		if d == nil || d.commitments == nil || d.share == nil || d.chainCodeCommit == nil {
			return false
		}
	}
	return true
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
