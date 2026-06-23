package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type frostKeygenLocalMaterial struct {
	polynomial      []*fed.Scalar
	commitments     *keygenCommitments
	localShare      *secret.Scalar
	chainCode       []byte
	chainCodeCommit []byte
	ownMessages     []tss.Envelope
}

// Destroy clears secret local keygen material.
func (m *frostKeygenLocalMaterial) Destroy() {
	if m == nil {
		return
	}
	clearScalars(m.polynomial)
	m.polynomial = nil
	m.commitments = nil
	if m.localShare != nil {
		m.localShare.Destroy()
		m.localShare = nil
	}
	clear(m.chainCode)
	m.chainCode = nil
	clear(m.chainCodeCommit)
	m.chainCodeCommit = nil
	clearEnvelopePayloads(m.ownMessages)
	m.ownMessages = nil
}

type frostKeygenRound1Slot struct {
	commitments     *keygenCommitments
	share           *secret.Scalar
	chainCodeCommit []byte
}

type frostKeygenRound1Inbox struct {
	parties tss.PartySet
	slots   map[tss.PartyID]*frostKeygenRound1Slot
}

func newFROSTKeygenRound1Inbox(parties tss.PartySet) *frostKeygenRound1Inbox {
	in := &frostKeygenRound1Inbox{
		parties: parties.Clone(),
		slots:   make(map[tss.PartyID]*frostKeygenRound1Slot, len(parties)),
	}
	for _, id := range parties {
		in.slots[id] = &frostKeygenRound1Slot{}
	}
	return in
}

func (in *frostKeygenRound1Inbox) slot(id tss.PartyID) (*frostKeygenRound1Slot, error) {
	if in == nil {
		return nil, errors.New("nil keygen round1 inbox")
	}
	slot, ok := in.slots[id]
	if !ok || slot == nil {
		return nil, fmt.Errorf("party %d is not a keygen participant", id)
	}
	return slot, nil
}

func (in *frostKeygenRound1Inbox) recordLocalFor(party tss.PartyID, commitments keygenCommitments, share *secret.Scalar, chainCodeCommit []byte) error {
	slot, err := in.slot(party)
	if err != nil {
		return err
	}
	clone := commitments.Clone()
	slot.commitments = &clone
	slot.share = share.Clone()
	slot.chainCodeCommit = bytes.Clone(chainCodeCommit)
	return nil
}

func (in *frostKeygenRound1Inbox) snapshot() (*frostKeygenRound1Snapshot, bool, error) {
	if in == nil {
		return nil, false, errors.New("nil keygen round1 inbox")
	}
	snap := &frostKeygenRound1Snapshot{
		parties:          in.parties.Clone(),
		commitments:      make(map[tss.PartyID]*keygenCommitments, len(in.parties)),
		shares:           make(map[tss.PartyID]*secret.Scalar, len(in.parties)),
		chainCodeCommits: make(map[tss.PartyID][]byte, len(in.parties)),
	}
	for _, id := range in.parties {
		slot, ok := in.slots[id]
		if !ok || slot == nil {
			snap.Destroy()
			return nil, false, fmt.Errorf("missing keygen round1 slot for party %d", id)
		}
		if slot.commitments == nil || slot.share == nil || slot.chainCodeCommit == nil {
			snap.Destroy()
			return nil, false, nil
		}
		commitments := slot.commitments.Clone()
		snap.commitments[id] = &commitments
		snap.shares[id] = slot.share.Clone()
		snap.chainCodeCommits[id] = bytes.Clone(slot.chainCodeCommit)
	}
	return snap, true, nil
}

// DestroySecrets clears secret shares accepted by the round-1 inbox.
func (in *frostKeygenRound1Inbox) DestroySecrets() {
	if in == nil {
		return
	}
	for _, slot := range in.slots {
		if slot != nil && slot.share != nil {
			slot.share.Destroy()
			slot.share = nil
		}
	}
}

type frostKeygenRound1Snapshot struct {
	parties          tss.PartySet
	commitments      map[tss.PartyID]*keygenCommitments
	shares           map[tss.PartyID]*secret.Scalar
	chainCodeCommits map[tss.PartyID][]byte
}

// Destroy clears secret shares owned by the round-1 snapshot.
func (s *frostKeygenRound1Snapshot) Destroy() {
	if s == nil {
		return
	}
	clearSecretScalarMap(s.shares)
	s.shares = nil
}

type frostKeygenConfirmationInbox struct {
	parties       tss.PartySet
	confirmations map[tss.PartyID]*KeygenConfirmation
	chainCodes    map[tss.PartyID][]byte
}

func newFROSTKeygenConfirmationInbox(parties tss.PartySet) *frostKeygenConfirmationInbox {
	return &frostKeygenConfirmationInbox{
		parties:       parties.Clone(),
		confirmations: make(map[tss.PartyID]*KeygenConfirmation, len(parties)),
		chainCodes:    make(map[tss.PartyID][]byte, len(parties)),
	}
}

func (in *frostKeygenConfirmationInbox) snapshot() (*frostKeygenConfirmationSnapshot, bool, error) {
	if in == nil {
		return nil, false, errors.New("nil keygen confirmation inbox")
	}
	snap := &frostKeygenConfirmationSnapshot{
		confirmations: make([]*KeygenConfirmation, 0, len(in.parties)),
		chainCodes:    make(map[tss.PartyID][]byte, len(in.parties)),
	}
	for _, id := range in.parties {
		confirmation, ok := in.confirmations[id]
		if !ok || confirmation == nil {
			snap.Destroy()
			return nil, false, nil
		}
		chainCode, ok := in.chainCodes[id]
		if !ok || chainCode == nil {
			snap.Destroy()
			return nil, false, fmt.Errorf("missing keygen chain code reveal for party %d", id)
		}
		snap.confirmations = append(snap.confirmations, confirmation.Clone())
		snap.chainCodes[id] = bytes.Clone(chainCode)
	}
	return snap, true, nil
}

// ClearReveals clears chain code reveals retained by the confirmation inbox.
func (in *frostKeygenConfirmationInbox) ClearReveals() {
	if in == nil {
		return
	}
	for id, chainCode := range in.chainCodes {
		clear(chainCode)
		delete(in.chainCodes, id)
	}
	for id, confirmation := range in.confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(in.confirmations, id)
	}
}

type frostKeygenConfirmationSnapshot struct {
	confirmations []*KeygenConfirmation
	chainCodes    map[tss.PartyID][]byte
}

// Destroy clears chain code reveals owned by the confirmation snapshot.
func (s *frostKeygenConfirmationSnapshot) Destroy() {
	if s == nil {
		return
	}
	for i, confirmation := range s.confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		s.confirmations[i] = nil
	}
	for id, chainCode := range s.chainCodes {
		clear(chainCode)
		delete(s.chainCodes, id)
	}
}

type frostPendingKeyShare struct {
	party                tss.PartyID
	threshold            int
	parties              tss.PartySet
	publicKey            PublicKeyPoint
	secret               *secret.Scalar
	groupCommitments     groupCommitments
	partyData            map[tss.PartyID]keySharePartyData
	keygenSessionID      tss.SessionID
	keygenTranscriptHash []byte
	planHash             []byte
	localChainCode       []byte
}

// Destroy clears secret material owned by the pending key share.
func (p *frostPendingKeyShare) Destroy() {
	if p == nil {
		return
	}
	if p.secret != nil {
		p.secret.Destroy()
		p.secret = nil
	}
	clear(p.localChainCode)
	p.localChainCode = nil
	clear(p.keygenTranscriptHash)
	p.keygenTranscriptHash = nil
	clear(p.planHash)
	p.planHash = nil
}

func (p *frostPendingKeyShare) confirmationReference(sender tss.PartyID, chainCode []byte) (*KeygenConfirmation, error) {
	if p == nil {
		return nil, errors.New("nil pending key share")
	}
	if !slices.Contains(p.parties, sender) {
		return nil, fmt.Errorf("confirmation sender %d is not a participant", sender)
	}
	return &KeygenConfirmation{
		SessionID:       p.keygenSessionID,
		Sender:          sender,
		Threshold:       p.threshold,
		Parties:         p.parties.Clone(),
		PublicKey:       p.publicKey.Clone(),
		TranscriptHash:  bytes.Clone(p.keygenTranscriptHash),
		CommitmentsHash: keygenGroupCommitmentsHash(p.groupCommitments.BytesList()),
		ChainCode:       bytes.Clone(chainCode),
		PlanHash:        bytes.Clone(p.planHash),
	}, nil
}
