package secp256k1

import "github.com/islishude/tss"

type cggmpKeygenSnapshot struct {
	Completed bool
	Aborted   bool
	State     keygenState

	HasPending  bool
	HasKeyShare bool
	HasPaillier bool

	CommitmentSenders   tss.PartySet
	ShareSenders        tss.PartySet
	ConfirmationSenders tss.PartySet
}

type cggmpPresignSnapshot struct {
	Completed bool
	Aborted   bool

	Round1PayloadSenders  tss.PartySet
	Round1ProofSenders    tss.PartySet
	Round1VerifiedSenders tss.PartySet

	Round2Senders           tss.PartySet
	AlphaDeltaSenders       tss.PartySet
	AlphaSigmaSenders       tss.PartySet
	BetaDeltaSenders        tss.PartySet
	BetaSigmaSenders        tss.PartySet
	Round3DeltaSenders      tss.PartySet
	Round3VerifyShareSender tss.PartySet

	Round2Sent bool
	Round3Sent bool

	HasKShare       bool
	HasGamma        bool
	HasXBar         bool
	HasStartOpening bool
	HasPresign      bool
	PresignReturned bool
}

type cggmpSignSnapshot struct {
	Completed bool
	Aborted   bool

	HasSignature   bool
	PartialSenders tss.PartySet
	HasAttempt     bool
	HasCoordinator bool
}

func snapshotCGGMPKeygenSession(s *KeygenSession) cggmpKeygenSnapshot {
	if s == nil {
		return cggmpKeygenSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := cggmpKeygenSnapshot{
		Completed:   s.completed,
		Aborted:     s.aborted,
		State:       s.state,
		HasPending:  s.pending != nil,
		HasKeyShare: s.keyShare != nil,
		HasPaillier: s.local != nil && s.local.paillier != nil,
	}
	if s.round1 != nil {
		for id, data := range s.round1.slots {
			if data == nil {
				continue
			}
			if len(data.commitments) != 0 {
				snap.CommitmentSenders = append(snap.CommitmentSenders, id)
			}
			if data.share != nil {
				snap.ShareSenders = append(snap.ShareSenders, id)
			}
		}
	}
	if s.confirmations != nil {
		for id, data := range s.confirmations.slots {
			if data != nil {
				snap.ConfirmationSenders = append(snap.ConfirmationSenders, id)
			}
		}
	}
	snap.CommitmentSenders = snap.CommitmentSenders.Sorted()
	snap.ShareSenders = snap.ShareSenders.Sorted()
	snap.ConfirmationSenders = snap.ConfirmationSenders.Sorted()
	return snap
}

func snapshotCGGMPPresignSession(s *PresignSession) cggmpPresignSnapshot {
	if s == nil {
		return cggmpPresignSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := cggmpPresignSnapshot{
		Completed:       s.completed,
		Aborted:         s.aborted,
		Round2Sent:      s.round2Sent,
		Round3Sent:      s.round3Sent,
		HasKShare:       s.kShare != nil,
		HasGamma:        s.gamma != nil,
		HasXBar:         s.xBar != nil,
		HasStartOpening: s.startOpening != nil,
		HasPresign:      s.presign != nil,
		PresignReturned: s.presignReturned,
	}
	for _, state := range s.parties {
		if state.round1.havePayload {
			snap.Round1PayloadSenders = append(snap.Round1PayloadSenders, state.id)
		}
		if state.round1.haveProof {
			snap.Round1ProofSenders = append(snap.Round1ProofSenders, state.id)
		}
		if state.round1.verified {
			snap.Round1VerifiedSenders = append(snap.Round1VerifiedSenders, state.id)
		}
		if state.round2.havePayload {
			snap.Round2Senders = append(snap.Round2Senders, state.id)
		}
		if state.mta.alphaDelta != nil {
			snap.AlphaDeltaSenders = append(snap.AlphaDeltaSenders, state.id)
		}
		if state.mta.alphaSigma != nil {
			snap.AlphaSigmaSenders = append(snap.AlphaSigmaSenders, state.id)
		}
		if state.mta.betaDelta != nil {
			snap.BetaDeltaSenders = append(snap.BetaDeltaSenders, state.id)
		}
		if state.mta.betaSigma != nil {
			snap.BetaSigmaSenders = append(snap.BetaSigmaSenders, state.id)
		}
		if state.round3.haveDelta {
			snap.Round3DeltaSenders = append(snap.Round3DeltaSenders, state.id)
		}
		if state.round3.haveVerifyShare {
			snap.Round3VerifyShareSender = append(snap.Round3VerifyShareSender, state.id)
		}
	}
	snap.Round1PayloadSenders = snap.Round1PayloadSenders.Sorted()
	snap.Round1ProofSenders = snap.Round1ProofSenders.Sorted()
	snap.Round1VerifiedSenders = snap.Round1VerifiedSenders.Sorted()
	snap.Round2Senders = snap.Round2Senders.Sorted()
	snap.AlphaDeltaSenders = snap.AlphaDeltaSenders.Sorted()
	snap.AlphaSigmaSenders = snap.AlphaSigmaSenders.Sorted()
	snap.BetaDeltaSenders = snap.BetaDeltaSenders.Sorted()
	snap.BetaSigmaSenders = snap.BetaSigmaSenders.Sorted()
	snap.Round3DeltaSenders = snap.Round3DeltaSenders.Sorted()
	snap.Round3VerifyShareSender = snap.Round3VerifyShareSender.Sorted()
	return snap
}

func snapshotCGGMPSignSession(s *SignSession) cggmpSignSnapshot {
	if s == nil {
		return cggmpSignSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cggmpSignSnapshot{
		Completed:      s.completed,
		Aborted:        s.aborted,
		HasSignature:   s.signature != nil,
		PartialSenders: cggmpSnapshotMapKeys(s.partials),
		HasAttempt:     len(s.attempt.PresignContentID) != 0 || len(s.attempt.AttemptHash) != 0,
		HasCoordinator: s.coordinator != nil,
	}
}

func cggmpSnapshotMapKeys[V any](m map[tss.PartyID]V) tss.PartySet {
	if len(m) == 0 {
		return nil
	}
	out := make(tss.PartySet, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out.Sorted()
}
