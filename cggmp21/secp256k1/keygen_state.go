package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
)

// keygenLocalMaterial owns locally generated secret material until it is
// transferred into a pending KeyShare.
type keygenLocalMaterial struct {
	commitments     [][]byte
	localShare      *secret.Scalar
	chainCode       []byte
	chainCodeCommit []byte
	paillier        *pai.PrivateKey
	paillierPub     paillierPublicMaterial
	ringPedersen    ringPedersenPublicMaterial
	polynomial      shamir.Polynomial
}

// Destroy clears locally generated secret material.
func (m *keygenLocalMaterial) Destroy() {
	if m == nil {
		return
	}
	if m.localShare != nil {
		m.localShare.Destroy()
		m.localShare = nil
	}
	clear(m.chainCode)
	m.chainCode = nil
	if m.paillier != nil {
		m.paillier.Destroy()
		m.paillier = nil
	}
	clearSecpPolynomial(m.polynomial)
	m.polynomial = nil
	m.commitments = nil
	m.chainCodeCommit = nil
	m.paillierPub = paillierPublicMaterial{}
	m.ringPedersen = ringPedersenPublicMaterial{}
}

func (m *keygenLocalMaterial) clearPolynomial() {
	if m == nil {
		return
	}
	clearSecpPolynomial(m.polynomial)
	m.polynomial = nil
}

type keygenRound1Inbox struct {
	parties tss.PartySet
	slots   map[tss.PartyID]*keygenRound1Slot
}

type keygenRound1Slot struct {
	commitments     [][]byte
	share           *secret.Scalar
	chainCodeCommit []byte
	paillierPub     paillierPublicMaterial
	ringPedersen    ringPedersenPublicMaterial
}

func newKeygenRound1Inbox(parties tss.PartySet) *keygenRound1Inbox {
	in := &keygenRound1Inbox{
		parties: parties.Clone(),
		slots:   make(map[tss.PartyID]*keygenRound1Slot, len(parties)),
	}
	for _, id := range parties {
		in.slots[id] = new(keygenRound1Slot)
	}
	return in
}

func (in *keygenRound1Inbox) slot(id tss.PartyID) (*keygenRound1Slot, error) {
	if in == nil {
		return nil, errors.New("nil keygen round1 inbox")
	}
	slot, ok := in.slots[id]
	if !ok || slot == nil {
		return nil, fmt.Errorf("party %d is not a keygen participant", id)
	}
	return slot, nil
}

func (in *keygenRound1Inbox) recordLocal(id tss.PartyID, local *keygenLocalMaterial) error {
	if local == nil {
		return errors.New("nil keygen local material")
	}
	slot, err := in.slot(id)
	if err != nil {
		return err
	}
	slot.commitments = tss.CloneByteSlices(local.commitments)
	slot.share = local.localShare.Clone()
	slot.chainCodeCommit = bytes.Clone(local.chainCodeCommit)
	slot.paillierPub = paillierPublicMaterial{
		Party:     id,
		PublicKey: local.paillierPub.PublicKey.Clone(),
		Proof:     local.paillierPub.Proof.Clone(),
	}
	slot.ringPedersen = ringPedersenPublicMaterial{
		Party:  id,
		Params: local.ringPedersen.Params.Clone(),
		Proof:  local.ringPedersen.Proof.Clone(),
	}
	return nil
}

func (in *keygenRound1Inbox) recordCommitments(
	id tss.PartyID,
	commitments [][]byte,
	chainCodeCommit []byte,
	paillierPub paillierPublicMaterial,
	ringPedersen ringPedersenPublicMaterial,
) error {
	slot, err := in.slot(id)
	if err != nil {
		return err
	}
	if slot.commitments != nil {
		return fmt.Errorf("duplicate commitments from party %d", id)
	}
	slot.commitments = commitments
	slot.chainCodeCommit = chainCodeCommit
	slot.paillierPub = paillierPub
	slot.ringPedersen = ringPedersen
	return nil
}

func (in *keygenRound1Inbox) recordShare(id tss.PartyID, share *secret.Scalar) error {
	slot, err := in.slot(id)
	if err != nil {
		return err
	}
	if slot.share != nil {
		return fmt.Errorf("duplicate share from party %d", id)
	}
	slot.share = share
	return nil
}

func (in *keygenRound1Inbox) commitmentsComplete() bool {
	if in == nil {
		return false
	}
	for _, id := range in.parties {
		slot := in.slots[id]
		if slot == nil || slot.commitments == nil || slot.paillierPub.PublicKey == nil || slot.ringPedersen.Params == nil {
			return false
		}
	}
	return true
}

type keygenRound1Snapshot struct {
	parties          tss.PartySet
	shares           map[tss.PartyID]*secret.Scalar
	commitments      map[tss.PartyID][][]byte
	chainCodeCommits map[tss.PartyID][]byte
	paillier         map[tss.PartyID]paillierPublicMaterial
	ringPedersen     map[tss.PartyID]ringPedersenPublicMaterial
}

func (in *keygenRound1Inbox) snapshot() (*keygenRound1Snapshot, bool, error) {
	if in == nil {
		return nil, false, errors.New("nil keygen round1 inbox")
	}
	snap := &keygenRound1Snapshot{
		parties:          in.parties.Clone(),
		shares:           make(map[tss.PartyID]*secret.Scalar, len(in.parties)),
		commitments:      make(map[tss.PartyID][][]byte, len(in.parties)),
		chainCodeCommits: make(map[tss.PartyID][]byte, len(in.parties)),
		paillier:         make(map[tss.PartyID]paillierPublicMaterial, len(in.parties)),
		ringPedersen:     make(map[tss.PartyID]ringPedersenPublicMaterial, len(in.parties)),
	}
	for _, id := range in.parties {
		slot, ok := in.slots[id]
		if !ok || slot == nil {
			snap.Destroy()
			return nil, false, fmt.Errorf("missing keygen round1 slot for party %d", id)
		}
	}
	for _, id := range in.parties {
		slot := in.slots[id]
		if slot.commitments == nil || slot.share == nil || slot.chainCodeCommit == nil ||
			slot.paillierPub.PublicKey == nil || slot.paillierPub.Proof == nil ||
			slot.ringPedersen.Params == nil || slot.ringPedersen.Proof == nil {
			snap.Destroy()
			return nil, false, nil
		}
		snap.shares[id] = slot.share.Clone()
		snap.commitments[id] = tss.CloneByteSlices(slot.commitments)
		snap.chainCodeCommits[id] = bytes.Clone(slot.chainCodeCommit)
		snap.paillier[id] = paillierPublicMaterial{
			Party:     id,
			PublicKey: slot.paillierPub.PublicKey.Clone(),
			Proof:     slot.paillierPub.Proof.Clone(),
		}
		snap.ringPedersen[id] = ringPedersenPublicMaterial{
			Party:  id,
			Params: slot.ringPedersen.Params.Clone(),
			Proof:  slot.ringPedersen.Proof.Clone(),
		}
	}
	return snap, true, nil
}

// Destroy clears caller-owned secret shares in the snapshot.
func (s *keygenRound1Snapshot) Destroy() {
	if s == nil {
		return
	}
	for id, share := range s.shares {
		share.Destroy()
		delete(s.shares, id)
	}
}

// Destroy clears accepted secret shares in the inbox.
func (in *keygenRound1Inbox) Destroy() {
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

type keygenConfirmationInbox struct {
	parties tss.PartySet
	slots   map[tss.PartyID]*KeygenConfirmation
	reveals map[tss.PartyID][]byte
}

func newKeygenConfirmationInbox(parties tss.PartySet) *keygenConfirmationInbox {
	return &keygenConfirmationInbox{
		parties: parties.Clone(),
		slots:   make(map[tss.PartyID]*KeygenConfirmation, len(parties)),
		reveals: make(map[tss.PartyID][]byte, len(parties)),
	}
}

func (in *keygenConfirmationInbox) confirmation(id tss.PartyID) (*KeygenConfirmation, bool, error) {
	if in == nil || !tss.ContainsParty(in.parties, id) {
		return nil, false, fmt.Errorf("party %d is not a keygen participant", id)
	}
	c, ok := in.slots[id]
	return c, ok, nil
}

func (in *keygenConfirmationInbox) record(id tss.PartyID, confirmation *KeygenConfirmation) error {
	if confirmation == nil {
		return errors.New("nil keygen confirmation")
	}
	if in == nil || !tss.ContainsParty(in.parties, id) {
		return fmt.Errorf("party %d is not a keygen participant", id)
	}
	if _, ok := in.slots[id]; ok {
		return fmt.Errorf("duplicate keygen confirmation from party %d", id)
	}
	in.slots[id] = confirmation
	in.reveals[id] = bytes.Clone(confirmation.ChainCode)
	return nil
}

type keygenConfirmationSnapshot struct {
	confirmations []*KeygenConfirmation
	chainCodes    map[tss.PartyID][]byte
}

func (in *keygenConfirmationInbox) snapshot() (*keygenConfirmationSnapshot, bool, error) {
	if in == nil {
		return nil, false, errors.New("nil keygen confirmation inbox")
	}
	snap := &keygenConfirmationSnapshot{
		confirmations: make([]*KeygenConfirmation, len(in.parties)),
		chainCodes:    make(map[tss.PartyID][]byte, len(in.parties)),
	}
	for i, id := range in.parties {
		c, ok := in.slots[id]
		if !ok {
			snap.Destroy()
			return nil, false, nil
		}
		if c == nil || c.Sender != id {
			snap.Destroy()
			return nil, false, fmt.Errorf("invalid keygen confirmation slot for party %d", id)
		}
		reveal, ok := in.reveals[id]
		if !ok || len(reveal) == 0 {
			snap.Destroy()
			return nil, false, fmt.Errorf("missing keygen chain code reveal for party %d", id)
		}
		snap.confirmations[i] = c.Clone()
		snap.chainCodes[id] = bytes.Clone(reveal)
	}
	return snap, true, nil
}

// Destroy clears caller-owned chain-code reveals in the snapshot.
func (s *keygenConfirmationSnapshot) Destroy() {
	if s == nil {
		return
	}
	for _, confirmation := range s.confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
	}
	for id, reveal := range s.chainCodes {
		clear(reveal)
		delete(s.chainCodes, id)
	}
}

// Destroy clears accepted chain-code reveals in the inbox.
func (in *keygenConfirmationInbox) Destroy() {
	if in == nil {
		return
	}
	for id, confirmation := range in.slots {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(in.slots, id)
	}
	for id, reveal := range in.reveals {
		clear(reveal)
		delete(in.reveals, id)
	}
}

func aggregateKeygenCommitments(
	parties tss.PartySet,
	threshold int,
	commitments map[tss.PartyID][][]byte,
) ([]*secp.Point, error) {
	groupCommitments := make([]*secp.Point, threshold)
	for degree := range threshold {
		points := make([]*secp.Point, 0, len(parties))
		for _, id := range parties {
			partyCommitments, ok := commitments[id]
			if !ok || len(partyCommitments) != threshold {
				return nil, fmt.Errorf("invalid commitments for party %d", id)
			}
			point, err := secp.PointFromBytes(partyCommitments[degree])
			if err != nil {
				return nil, err
			}
			points = append(points, point)
		}
		groupCommitments[degree] = secp.AddPoints(points...)
	}
	return groupCommitments, nil
}
