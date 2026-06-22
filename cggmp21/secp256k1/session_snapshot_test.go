package secp256k1

import "github.com/islishude/tss"

type cggmpKeygenSnapshot struct {
	Completed bool
	Aborted   bool
	State     keygenState

	HasPending  bool
	HasKeyShare bool
	HasPaillier bool

	CommitmentSenders   []tss.PartyID
	ShareSenders        []tss.PartyID
	ConfirmationSenders []tss.PartyID
}

type cggmpPresignSnapshot struct {
	Completed bool
	Aborted   bool

	Round1PayloadSenders  []tss.PartyID
	Round1ProofSenders    []tss.PartyID
	Round1VerifiedSenders []tss.PartyID

	Round2Senders           []tss.PartyID
	AlphaDeltaSenders       []tss.PartyID
	AlphaSigmaSenders       []tss.PartyID
	BetaDeltaSenders        []tss.PartyID
	BetaSigmaSenders        []tss.PartyID
	Round3DeltaSenders      []tss.PartyID
	Round3VerifyShareSender []tss.PartyID

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
	PartialSenders []tss.PartyID
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
		HasPaillier: s.paillier != nil,
	}
	for id, data := range s.partyData {
		if data == nil {
			continue
		}
		if len(data.commitments) != 0 {
			snap.CommitmentSenders = append(snap.CommitmentSenders, id)
		}
		if data.share != nil {
			snap.ShareSenders = append(snap.ShareSenders, id)
		}
		if data.confirmation != nil {
			snap.ConfirmationSenders = append(snap.ConfirmationSenders, id)
		}
	}
	snap.CommitmentSenders = tss.PartySet(snap.CommitmentSenders).Sorted()
	snap.ShareSenders = tss.PartySet(snap.ShareSenders).Sorted()
	snap.ConfirmationSenders = tss.PartySet(snap.ConfirmationSenders).Sorted()
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
	snap.Round1PayloadSenders = tss.PartySet(snap.Round1PayloadSenders).Sorted()
	snap.Round1ProofSenders = tss.PartySet(snap.Round1ProofSenders).Sorted()
	snap.Round1VerifiedSenders = tss.PartySet(snap.Round1VerifiedSenders).Sorted()
	snap.Round2Senders = tss.PartySet(snap.Round2Senders).Sorted()
	snap.AlphaDeltaSenders = tss.PartySet(snap.AlphaDeltaSenders).Sorted()
	snap.AlphaSigmaSenders = tss.PartySet(snap.AlphaSigmaSenders).Sorted()
	snap.BetaDeltaSenders = tss.PartySet(snap.BetaDeltaSenders).Sorted()
	snap.BetaSigmaSenders = tss.PartySet(snap.BetaSigmaSenders).Sorted()
	snap.Round3DeltaSenders = tss.PartySet(snap.Round3DeltaSenders).Sorted()
	snap.Round3VerifyShareSender = tss.PartySet(snap.Round3VerifyShareSender).Sorted()
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

func cggmpSnapshotMapKeys[V any](m map[tss.PartyID]V) []tss.PartyID {
	if len(m) == 0 {
		return nil
	}
	out := make(tss.PartySet, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out.Sorted()
}
