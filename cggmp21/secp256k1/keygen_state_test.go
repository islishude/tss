package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestKeygenRound1SnapshotIncompleteAndCorruptState(t *testing.T) {
	t.Parallel()
	parties := tss.NewPartySet(1, 2)
	in := newKeygenRound1Inbox(parties)
	if snap, ok, err := in.snapshot(); err != nil || ok || snap != nil {
		t.Fatalf("empty snapshot = (%v, %v, %v), want incomplete", snap, ok, err)
	}
	delete(in.slots, 2)
	if snap, ok, err := in.snapshot(); err == nil || ok || snap != nil {
		t.Fatalf("corrupt snapshot = (%v, %v, %v), want error", snap, ok, err)
	}
}

func TestKeygenRound1SnapshotCompleteIsCallerOwned(t *testing.T) {
	t.Parallel()
	parties := tss.NewPartySet(1)
	in := newKeygenRound1Inbox(parties)
	slot := in.slots[1]
	slot.commitments = [][]byte{{1}}
	slot.share = testSecretScalar(t, 1)
	slot.chainCodeCommit = bytes.Repeat([]byte{2}, 32)
	slot.paillierPub = paillierPublicMaterial{
		Party:     1,
		PublicKey: &pai.PublicKey{},
		Proof:     &zkpai.ModulusProof{},
	}
	slot.ringPedersen = ringPedersenPublicMaterial{
		Party:  1,
		Params: &zkpai.RingPedersenParams{},
		Proof:  &zkpai.RingPedersenProof{},
	}
	snap, ok, err := in.snapshot()
	if err != nil || !ok {
		t.Fatalf("snapshot: ok=%v err=%v", ok, err)
	}
	defer snap.Destroy()
	snap.commitments[1][0][0] ^= 1
	if in.slots[1].commitments[0][0] != 1 {
		t.Fatal("snapshot mutation changed inbox commitments")
	}
}

func TestKeygenConfirmationSnapshotOrdersByParty(t *testing.T) {
	t.Parallel()
	in := newKeygenConfirmationInbox(tss.NewPartySet(1, 2, 3))
	for _, id := range []tss.PartyID{3, 1, 2} {
		if err := in.record(id, &KeygenConfirmation{
			Sender:    id,
			ChainCode: bytes.Repeat([]byte{byte(id)}, bip32util.ChainCodeSize),
		}); err != nil {
			t.Fatal(err)
		}
	}
	snap, ok, err := in.snapshot()
	if err != nil || !ok {
		t.Fatalf("snapshot: ok=%v err=%v", ok, err)
	}
	defer snap.Destroy()
	for i, id := range tss.NewPartySet(1, 2, 3) {
		if snap.confirmations[i].Sender != id {
			t.Fatalf("confirmation[%d].Sender = %d, want %d", i, snap.confirmations[i].Sender, id)
		}
	}
}

func TestConfirmationChainCodePoliciesAreExplicit(t *testing.T) {
	t.Parallel()
	sessionID := cggmpPlanTestSession(0x45)
	chainCode := bytes.Repeat([]byte{0x31}, bip32util.ChainCodeSize)
	commitment := bip32util.ChainCodeCommitment(cggmpChainCodeCommitLabel, sessionID, 2, chainCode)
	if err := verifyConfirmationCommitRevealChainCode(sessionID, 2, chainCode, commitment); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(chainCode)
	tampered[0] ^= 1
	if err := verifyConfirmationCommitRevealChainCode(sessionID, 2, tampered, commitment); err == nil {
		t.Fatal("tampered commit-reveal chain code accepted")
	}
	confirmation := &KeygenConfirmation{Sender: 2, ChainCode: bytes.Clone(chainCode)}
	if err := verifyConfirmationPreservedChainCode(chainCode, confirmation); err != nil {
		t.Fatal(err)
	}
	if err := verifyConfirmationPreservedChainCode(tampered, confirmation); err == nil {
		t.Fatal("mismatched preserved chain code accepted")
	}
}

func TestDeriveVerificationShareSetCoversEveryParty(t *testing.T) {
	t.Parallel()
	parties := tss.NewPartySet(1, 2, 3)
	commitments := []*secp.Point{
		secp.ScalarBaseMult(secp.ScalarFromUint64(3)),
		secp.ScalarBaseMult(secp.ScalarFromUint64(5)),
	}
	shares, err := deriveVerificationShareSet(parties, commitments)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != len(parties) {
		t.Fatalf("got %d verification shares, want %d", len(shares), len(parties))
	}
	for _, id := range parties {
		if len(shares[id]) == 0 {
			t.Fatalf("missing verification share for party %d", id)
		}
	}
}
