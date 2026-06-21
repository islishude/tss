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
	prepared, ok, err := s.maybePreparePendingKeyShare()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer prepared.destroy()
	effects := s.commitPendingKeyShare(prepared)
	if allConfirmationsReceived(s.partyData, s.cfg.Parties) {
		if err := s.finalizeConfirmedKeyShare(); err != nil {
			return nil, err
		}
	}
	return effects.envelopes, nil
}

type preparedPendingKeyShare struct {
	share        *KeyShare
	confirmation *KeygenConfirmation
	env          tss.Envelope
	committed    bool
}

func (p *preparedPendingKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
		p.share = nil
	}
	if p.confirmation != nil {
		clear(p.confirmation.ChainCode)
		p.confirmation = nil
	}
	clear(p.env.Payload)
}

func (s *KeygenSession) maybePreparePendingKeyShare() (*preparedPendingKeyShare, bool, error) {
	if s.completed || s.pending != nil {
		return nil, false, nil
	}
	if !allRound1Received(s.partyData, s.cfg.Parties) {
		return nil, false, nil
	}
	for _, id := range s.cfg.Parties {
		d := s.partyData[id]
		share, err := edScalarFromSecret(d.share)
		if err != nil {
			return nil, false, err
		}
		// Verify f_dealer(self) * B against the dealer's public polynomial commitments.
		verifyErr := d.commitments.VerifyShare(s.cfg.Self, share)
		share.Set(fed.NewScalar())
		if verifyErr != nil {
			s.cfg.Logger().Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", id,
			)
			return nil, false, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: keygenStartRound,
				Party: id,
				Blame: frostKeygenBlame(s.cfg, id, d.commitments.BytesList()),
				Err:   verifyErr,
			}
		}
	}
	secret := fed.NewScalar()
	for _, id := range s.cfg.Parties {
		share, err := edScalarFromSecret(s.partyData[id].share)
		if err != nil {
			secret.Set(fed.NewScalar())
			return nil, false, err
		}
		secret.Add(secret, share)
		share.Set(fed.NewScalar())
	}
	secretScalar, err := newEdSecretScalar(secret.Bytes())
	secret.Set(fed.NewScalar())
	if err != nil {
		return nil, false, err
	}
	groupPoints := make([]*fed.Point, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*fed.Point, 0, len(s.cfg.Parties))
		for _, id := range s.cfg.Parties {
			p, err := s.partyData[id].commitments.PointAt(degree)
			if err != nil {
				secretScalar.Destroy()
				return nil, false, err
			}
			points = append(points, p)
		}
		// Summing same-degree commitments yields the public polynomial for the group secret.
		groupPoints[degree] = edcurve.AddPoints(points...)
	}
	groupCommitments, err := newGroupCommitmentsFromPoints(groupPoints, s.cfg.Threshold)
	if err != nil {
		secretScalar.Destroy()
		return nil, false, fmt.Errorf("invalid group public key: %w", err)
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := groupCommitments.Eval(id)
		if err != nil {
			secretScalar.Destroy()
			return nil, false, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub.Clone()})
		partyData[id] = keySharePartyData{verificationShare: pub}
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
		secretScalar.Destroy()
		return nil, false, err
	}
	dealerCommits := make(map[tss.PartyID][][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		dealerCommits[id] = s.partyData[id].commitments.BytesList()
	}
	keygenTranscriptHash := frostKeygenTranscriptHash(s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties, chainCodeCommitAggregate, s.planHash, dealerCommits, groupCommitments.BytesList(), verificationShares)
	share := &KeyShare{state: &keyShareState{
		party:                s.cfg.Self,
		threshold:            s.cfg.Threshold,
		parties:              s.cfg.Parties.Clone(),
		publicKey:            groupCommitments.PublicKey(),
		chainCode:            bytes.Clone(s.partyData[s.cfg.Self].chainCode),
		secret:               secretScalar,
		groupCommitments:     groupCommitments.Clone(),
		partyData:            partyData,
		keygenSessionID:      s.cfg.SessionID,
		keygenTranscriptHash: keygenTranscriptHash,
		planHash:             bytes.Clone(s.planHash),
	}}
	if err := share.validateConsistencyWithoutConfirmations(); err != nil {
		share.Destroy()
		return nil, false, err
	}
	confirmation, err := share.NewConfirmation()
	if err != nil {
		share.Destroy()
		return nil, false, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		clear(confirmation.ChainCode)
		share.Destroy()
		return nil, false, err
	}
	confirmationEnv, err := newEnvelope(s.cfg, keygenConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		clear(encodedConfirmation)
		clear(confirmation.ChainCode)
		share.Destroy()
		return nil, false, err
	}
	return &preparedPendingKeyShare{
		share:        share,
		confirmation: confirmation,
		env:          confirmationEnv,
	}, true, nil
}

func (s *KeygenSession) commitPendingKeyShare(p *preparedPendingKeyShare) sessionEffects {
	if p == nil {
		return sessionEffects{}
	}
	s.partyData[s.cfg.Self].confirmation = p.confirmation
	s.pending = p.share
	p.committed = true
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return sessionEffects{envelopes: []tss.Envelope{p.env}}
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
