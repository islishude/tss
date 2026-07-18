package secp256k1

import (
	"bytes"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

type cggmpKeygenSnapshot struct {
	Completed bool
	Aborted   bool
	State     keygenState

	HasPending        bool
	HasKeyShare       bool
	HasFigure6        bool
	HasAuxInfo        bool
	HasPaillier       bool
	HasFigure7Failure bool
	Figure6RevealSent bool
	Figure6ProofSent  bool
	AuxRevealSent     bool
	AuxProofsSent     bool
	PaperAccepted     int

	Figure6CommitmentSenders tss.PartySet
	Figure6RevealSenders     tss.PartySet
	Figure6ProofSenders      tss.PartySet
	AuxCommitmentSenders     tss.PartySet
	AuxRevealSenders         tss.PartySet
	AuxProofSenders          tss.PartySet
	AuxShareSenders          tss.PartySet
	ConfirmationSenders      tss.PartySet
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
	Round3PayloadSenders    tss.PartySet
	Round3DeltaSenders      tss.PartySet
	Round3ChiSenders        tss.PartySet
	Round3DeltaPointSenders tss.PartySet
	Round3SPointSenders     tss.PartySet
	Round3ProofSenders      tss.PartySet

	Identifying            bool
	RedAlertKind           presignRedAlertKind
	RedAlertDigest         []byte
	RedAlertPayloadSenders tss.PartySet

	Round2Sent bool
	Round3Sent bool

	HasKShare       bool
	HasGamma        bool
	HasXBar         bool
	HasStartOpening bool
	HasGammaOpening bool
	HasPersisted    bool
	LeaseFinished   bool
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
		Completed:         s.completed,
		Aborted:           s.aborted,
		State:             s.state,
		HasPending:        s.pending != nil,
		HasKeyShare:       s.keyShare != nil,
		HasFigure6:        s.figure6 != nil,
		HasAuxInfo:        s.auxInfo != nil,
		HasPaillier:       s.auxInfo != nil && s.auxInfo.local != nil && s.auxInfo.local.paillier != nil,
		HasFigure7Failure: s.figure7Failure != nil,
		PaperAccepted:     len(s.paperAccepted),
	}
	if s.figure6 != nil {
		snap.Figure6RevealSent = s.figure6.revealSent
		snap.Figure6ProofSent = s.figure6.proofSent
		for id, slot := range s.figure6.slots {
			if slot == nil {
				continue
			}
			if len(slot.commitment) != 0 {
				snap.Figure6CommitmentSenders = append(snap.Figure6CommitmentSenders, id)
			}
			if slot.reveal != nil {
				snap.Figure6RevealSenders = append(snap.Figure6RevealSenders, id)
			}
			if slot.proof != nil {
				snap.Figure6ProofSenders = append(snap.Figure6ProofSenders, id)
			}
		}
	}
	if s.auxInfo != nil {
		snap.AuxRevealSent = s.auxInfo.revealSent
		snap.AuxProofsSent = s.auxInfo.proofsSent
		for id, slot := range s.auxInfo.slots {
			if slot == nil {
				continue
			}
			if len(slot.commitment) != 0 {
				snap.AuxCommitmentSenders = append(snap.AuxCommitmentSenders, id)
			}
			if slot.reveal != nil {
				snap.AuxRevealSenders = append(snap.AuxRevealSenders, id)
			}
			if slot.proofs != nil || slot.modProof != nil || slot.factor != nil {
				snap.AuxProofSenders = append(snap.AuxProofSenders, id)
			}
			if slot.share != nil {
				snap.AuxShareSenders = append(snap.AuxShareSenders, id)
			}
		}
	}
	snap.ConfirmationSenders = testutil.SortedPartyMapKeys(s.paperConfirmations)
	snap.Figure6CommitmentSenders = snap.Figure6CommitmentSenders.Sorted()
	snap.Figure6RevealSenders = snap.Figure6RevealSenders.Sorted()
	snap.Figure6ProofSenders = snap.Figure6ProofSenders.Sorted()
	snap.AuxCommitmentSenders = snap.AuxCommitmentSenders.Sorted()
	snap.AuxRevealSenders = snap.AuxRevealSenders.Sorted()
	snap.AuxProofSenders = snap.AuxProofSenders.Sorted()
	snap.AuxShareSenders = snap.AuxShareSenders.Sorted()
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
		Completed:              s.completed,
		Aborted:                s.aborted,
		Identifying:            s.identifying,
		RedAlertKind:           s.redAlertKind,
		RedAlertDigest:         bytes.Clone(s.redAlertDigest),
		RedAlertPayloadSenders: testutil.SortedPartyMapKeys(s.redAlertPayloads),
		Round2Sent:             s.round2Sent,
		Round3Sent:             s.round3Sent,
		HasKShare:              s.kShare != nil,
		HasGamma:               s.gamma != nil,
		HasXBar:                s.xBar != nil,
		HasStartOpening:        s.startOpening != nil,
		HasGammaOpening:        s.gammaOpening != nil,
		HasPersisted:           s.persistedPresign != nil,
		LeaseFinished:          s.leaseFinished,
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
		if state.round3.havePayload {
			snap.Round3PayloadSenders = append(snap.Round3PayloadSenders, state.id)
		}
		if state.round3.delta != nil {
			snap.Round3DeltaSenders = append(snap.Round3DeltaSenders, state.id)
		}
		if state.round3.chi != nil {
			snap.Round3ChiSenders = append(snap.Round3ChiSenders, state.id)
		}
		if len(state.round3.deltaPoint) != 0 {
			snap.Round3DeltaPointSenders = append(snap.Round3DeltaPointSenders, state.id)
		}
		if len(state.round3.sPoint) != 0 {
			snap.Round3SPointSenders = append(snap.Round3SPointSenders, state.id)
		}
		if len(state.round3.proof.TranscriptHash) != 0 {
			snap.Round3ProofSenders = append(snap.Round3ProofSenders, state.id)
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
	snap.Round3PayloadSenders = snap.Round3PayloadSenders.Sorted()
	snap.Round3DeltaSenders = snap.Round3DeltaSenders.Sorted()
	snap.Round3ChiSenders = snap.Round3ChiSenders.Sorted()
	snap.Round3DeltaPointSenders = snap.Round3DeltaPointSenders.Sorted()
	snap.Round3SPointSenders = snap.Round3SPointSenders.Sorted()
	snap.Round3ProofSenders = snap.Round3ProofSenders.Sorted()
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
		PartialSenders: testutil.SortedPartyMapKeys(s.partials),
		HasAttempt:     s.attempt.PresignID != "" || s.attempt.Intent.AttemptID != "" || len(s.attempt.ExactOutbox) != 0,
		HasCoordinator: s.coordinator != nil,
	}
}
