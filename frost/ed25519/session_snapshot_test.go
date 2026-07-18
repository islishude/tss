package ed25519

import "github.com/islishude/tss"

type frostSignSnapshot struct {
	Completed bool
	Aborted   bool

	CommitmentSenders tss.PartySet
	PartialSenders    tss.PartySet

	PartialSent  bool
	HasDNonce    bool
	HasENonce    bool
	HasMessage   bool
	HasSignature bool
}

type frostKeygenSnapshot struct {
	Completed bool
	Aborted   bool

	HasPending  bool
	HasKeyShare bool

	CommitmentSenders   tss.PartySet
	ShareSenders        tss.PartySet
	ConfirmationSenders tss.PartySet

	OwnPolyLen     int
	OwnMessagesLen int
}

type frostReshareSnapshot struct {
	Completed bool
	Aborted   bool

	HasNewShare            bool
	HasPendingShare        bool
	HasConfirmationBinding bool
	IsReceiver             bool
	RefreshMode            bool

	CommitSenders              tss.PartySet
	ShareSenders               tss.PartySet
	ConfirmationSenders        tss.PartySet
	PendingConfirmationSenders tss.PartySet
}

func snapshotFROSTSignSession(s *SignSession) frostSignSnapshot {
	if s == nil {
		return frostSignSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return frostSignSnapshot{
		Completed:         s.completed,
		Aborted:           s.aborted,
		CommitmentSenders: frostSnapshotMapKeys(s.commitments),
		PartialSenders:    frostSnapshotMapKeys(s.partials),
		PartialSent:       s.partialSent,
		HasDNonce:         s.dNonce != nil,
		HasENonce:         s.eNonce != nil,
		HasMessage:        len(s.message) != 0,
		HasSignature:      len(s.signature) != 0,
	}
}

func snapshotFROSTKeygenSession(s *KeygenSession) frostKeygenSnapshot {
	if s == nil {
		return frostKeygenSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := frostKeygenSnapshot{
		Completed:   s.completed,
		Aborted:     s.aborted,
		HasPending:  s.pending != nil,
		HasKeyShare: s.keyShare != nil,
	}
	if s.local != nil {
		snap.OwnPolyLen = len(s.local.polynomial)
		snap.OwnMessagesLen = len(s.local.ownMessages)
	}
	for id, data := range s.round1.slots {
		if data == nil {
			continue
		}
		if data.commitments != nil {
			snap.CommitmentSenders = append(snap.CommitmentSenders, id)
		}
		if data.share != nil {
			snap.ShareSenders = append(snap.ShareSenders, id)
		}
		if s.confirmations.confirmations[id] != nil {
			snap.ConfirmationSenders = append(snap.ConfirmationSenders, id)
		}
	}
	snap.CommitmentSenders = snap.CommitmentSenders.Sorted()
	snap.ShareSenders = snap.ShareSenders.Sorted()
	snap.ConfirmationSenders = snap.ConfirmationSenders.Sorted()
	return snap
}

func snapshotFROSTReshareSession(s *ReshareSession) frostReshareSnapshot {
	if s == nil {
		return frostReshareSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return frostReshareSnapshot{
		Completed:                  s.completed,
		Aborted:                    s.aborted,
		HasNewShare:                s.newShare != nil,
		HasPendingShare:            s.pendingShare != nil,
		HasConfirmationBinding:     s.confirmationBinding != nil,
		IsReceiver:                 s.isReceiver(),
		RefreshMode:                s.isRefresh(),
		CommitSenders:              frostSnapshotMapKeys(s.commits),
		ShareSenders:               frostSnapshotMapKeys(s.shares),
		ConfirmationSenders:        frostSnapshotMapKeys(s.confirmations),
		PendingConfirmationSenders: frostSnapshotMapKeys(s.pendingConfirmations),
	}
}

func frostSnapshotMapKeys[V any](m map[tss.PartyID]V) tss.PartySet {
	if len(m) == 0 {
		return nil
	}
	out := make(tss.PartySet, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out.Sorted()
}
