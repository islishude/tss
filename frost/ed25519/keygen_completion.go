package ed25519

import (
	"bytes"
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

func (s *KeygenSession) tryAdvance() ([]tss.Envelope, error) {
	if s == nil || s.completed || s.aborted {
		return nil, nil
	}
	if s.pending == nil {
		snap, ok, err := s.round1.snapshot()
		if err != nil || !ok {
			return nil, err
		}
		defer snap.Destroy()
		return s.completeRound1(snap)
	}
	snap, ok, err := s.confirmations.snapshot()
	if err != nil || !ok {
		return nil, err
	}
	defer snap.Destroy()
	return nil, s.completeConfirmationRound(snap)
}

func (s *KeygenSession) completeRound1(snap *frostKeygenRound1Snapshot) ([]tss.Envelope, error) {
	prepared, err := s.preparePendingKeyMaterial(snap)
	if err != nil {
		return nil, err
	}
	defer prepared.destroy()
	out := s.commitPendingKeyShare(prepared)
	more, err := s.tryAdvance()
	if err != nil {
		return nil, err
	}
	return append(out, more...), nil
}

type preparedPendingKeyShare struct {
	pending      *frostPendingKeyShare
	confirmation *KeygenConfirmation
	env          tss.Envelope
	committed    bool
}

func (p *preparedPendingKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.pending != nil {
		p.pending.Destroy()
		p.pending = nil
	}
	if p.confirmation != nil {
		clear(p.confirmation.ChainCode)
		p.confirmation = nil
	}
	clear(p.env.Payload)
	p.env.Payload = nil
}

func (s *KeygenSession) preparePendingKeyMaterial(snap *frostKeygenRound1Snapshot) (*preparedPendingKeyShare, error) {
	if s.pending != nil || s.completed {
		return nil, errors.New("keygen round1 already completed")
	}
	if s.local == nil {
		return nil, errors.New("missing keygen local material")
	}
	if err := verifyFROSTKeygenShares(s.cfg, snap); err != nil {
		return nil, err
	}
	secretScalar, err := aggregateFROSTKeygenSecret(s.cfg.Parties, snap.shares)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			secretScalar.Destroy()
		}
	}()
	group, err := aggregateFROSTKeygenCommitments(s.cfg.Parties, s.cfg.Threshold, snap.commitments)
	if err != nil {
		return nil, tss.NewProtocolError(
			tss.ErrCodeVerification,
			keygenStartRound,
			tss.BroadcastPartyId,
			fmt.Errorf("invalid aggregate keygen commitments: %w", err),
		)
	}
	if s.importPlan != nil && !group.PublicKey().Equal(s.importPlan.state.PublicKey) {
		return nil, errors.New("trusted-dealer import produced the wrong group public key")
	}
	partyData, verificationShares, err := deriveFROSTVerificationShares(s.cfg.Parties, group)
	if err != nil {
		return nil, err
	}
	transcriptHash, err := buildFROSTKeygenTranscriptHash(s.cfg, s.planHash, snap, group, verificationShares)
	if err != nil {
		return nil, err
	}
	pending := &frostPendingKeyShare{
		party:                s.cfg.Self,
		threshold:            s.cfg.Threshold,
		parties:              s.cfg.Parties.Clone(),
		publicKey:            group.PublicKey(),
		secret:               secretScalar,
		groupCommitments:     group.Clone(),
		partyData:            partyData,
		keygenSessionID:      s.cfg.SessionID,
		keygenTranscriptHash: transcriptHash,
		planHash:             bytes.Clone(s.planHash),
		localChainCode:       bytes.Clone(s.local.chainCode),
	}
	confirmation, err := newFROSTKeygenConfirmation(pending)
	if err != nil {
		pending.Destroy()
		return nil, err
	}
	encoded, err := confirmation.MarshalBinary()
	if err != nil {
		clear(confirmation.ChainCode)
		pending.Destroy()
		return nil, err
	}
	env, err := newEnvelope(s.cfg, keygenConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encoded)
	clear(encoded)
	if err != nil {
		clear(confirmation.ChainCode)
		pending.Destroy()
		return nil, err
	}
	committed = true
	return &preparedPendingKeyShare{pending: pending, confirmation: confirmation, env: env}, nil
}

func (s *KeygenSession) commitPendingKeyShare(p *preparedPendingKeyShare) []tss.Envelope {
	if p == nil {
		return nil
	}
	s.confirmations.confirmations[s.cfg.Self] = p.confirmation
	s.confirmations.chainCodes[s.cfg.Self] = bytes.Clone(p.confirmation.ChainCode)
	s.pending = p.pending
	s.state = keygenAwaitingConfirmations
	if s.local != nil {
		s.local.Destroy()
		s.local = nil
	}
	s.round1.DestroySecrets()
	p.committed = true
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return []tss.Envelope{p.env}
}

func verifyFROSTKeygenShares(cfg tss.ThresholdConfig, snap *frostKeygenRound1Snapshot) error {
	for _, id := range cfg.Parties {
		share, err := edScalarFromSecret(snap.shares[id])
		if err != nil {
			return err
		}
		verifyErr := snap.commitments[id].VerifyShare(cfg.Self, share)
		share.Set(fed.NewScalar())
		if verifyErr != nil {
			cfg.Logger().Warn(cfg.Ctx(), "invalid DKG share", "party_id", cfg.Self, "dealer", id)
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: keygenStartRound,
				Party: id,
				Blame: frostKeygenBlame(cfg, id, snap.commitments[id].BytesList()),
				Err:   verifyErr,
			}
		}
	}
	return nil
}

func aggregateFROSTKeygenSecret(parties tss.PartySet, shares map[tss.PartyID]*secret.Scalar) (*secret.Scalar, error) {
	total := fed.NewScalar()
	for _, id := range parties {
		share, err := edScalarFromSecret(shares[id])
		if err != nil {
			total.Set(fed.NewScalar())
			return nil, err
		}
		total.Add(total, share)
		share.Set(fed.NewScalar())
	}
	out, err := newEdSecretScalarFromFed(total)
	total.Set(fed.NewScalar())
	return out, err
}

func aggregateFROSTKeygenCommitments(parties tss.PartySet, threshold int, commitments map[tss.PartyID]*keygenCommitments) (groupCommitments, error) {
	points := make([]*fed.Point, threshold)
	for degree := range threshold {
		degreePoints := make([]*fed.Point, 0, len(parties))
		for _, id := range parties {
			point, err := commitments[id].PointAt(degree)
			if err != nil {
				return groupCommitments{}, err
			}
			degreePoints = append(degreePoints, point)
		}
		points[degree] = edcurve.AddPoints(degreePoints...)
	}
	group, err := newGroupCommitmentsFromPoints(points, threshold)
	if err != nil {
		return groupCommitments{}, fmt.Errorf("invalid group public key: %w", err)
	}
	return group, nil
}

func deriveFROSTVerificationShares(parties tss.PartySet, group groupCommitments) (map[tss.PartyID]keySharePartyData, []VerificationShare, error) {
	partyData := make(map[tss.PartyID]keySharePartyData, len(parties))
	verificationShares := make([]VerificationShare, 0, len(parties))
	for _, id := range parties {
		public, err := group.Eval(id)
		if err != nil {
			return nil, nil, err
		}
		partyData[id] = keySharePartyData{VerificationShare: public}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: public.Clone()})
	}
	return partyData, verificationShares, nil
}

func buildFROSTKeygenTranscriptHash(cfg tss.ThresholdConfig, planHash []byte, snap *frostKeygenRound1Snapshot, group groupCommitments, verificationShares []VerificationShare) ([]byte, error) {
	chainCodeCommits := make(map[tss.PartyID][]byte, len(cfg.Parties))
	dealerCommits := make(map[tss.PartyID][][]byte, len(cfg.Parties))
	for _, id := range cfg.Parties {
		chainCodeCommits[id] = snap.chainCodeCommits[id]
		dealerCommits[id] = snap.commitments[id].BytesList()
	}
	aggregate, err := bip32util.AggregateChainCode(cfg.Parties, chainCodeCommits)
	if err != nil {
		return nil, err
	}
	return frostKeygenTranscriptHash(
		cfg.SessionID,
		cfg.Threshold,
		cfg.Parties,
		aggregate,
		planHash,
		dealerCommits,
		group.BytesList(),
		verificationShares,
	), nil
}
