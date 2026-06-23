package ed25519

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
)

func TestFROSTKeygenRound1SnapshotRequiresCompleteSlots(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	installFROSTKeygenRound1(t, session, remoteOut)

	remote := session.round1.slots[2]
	tests := []struct {
		name   string
		mutate func()
		reset  func()
	}{
		{
			name: "commitments",
			mutate: func() {
				remote.commitments = nil
			},
			reset: func() {
				payload := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)
				decoded, err := unmarshalKeygenCommitmentsPayload(payload.Payload)
				if err != nil {
					t.Fatal(err)
				}
				commitments := decoded.Commitments.Clone()
				remote.commitments = &commitments
			},
		},
		{
			name: "share",
			mutate: func() {
				remote.share.Destroy()
				remote.share = nil
			},
			reset: func() {
				payload := mustFROSTEnvelope(t, remoteOut, payloadKeygenShare, session.cfg.Self)
				decoded, err := unmarshalKeygenSharePayload(payload.Payload)
				if err != nil {
					t.Fatal(err)
				}
				remote.share = decoded.Share
			},
		},
		{
			name: "chain code commitment",
			mutate: func() {
				remote.chainCodeCommit = nil
			},
			reset: func() {
				payload := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)
				decoded, err := unmarshalKeygenCommitmentsPayload(payload.Payload)
				if err != nil {
					t.Fatal(err)
				}
				remote.chainCodeCommit = bytes.Clone(decoded.ChainCodeCommit)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.mutate()
			snap, ok, err := session.round1.snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if ok || snap != nil {
				t.Fatal("incomplete round1 inbox produced a snapshot")
			}
			test.reset()
		})
	}
}

func TestFROSTKeygenRound1SnapshotRejectsMissingPartySlot(t *testing.T) {
	t.Parallel()

	inbox := newFROSTKeygenRound1Inbox(tss.NewPartySet(1, 2))
	delete(inbox.slots, 1)
	if snap, ok, err := inbox.snapshot(); err == nil || ok || snap != nil {
		t.Fatalf("snapshot = (%v, %v, %v), want missing-slot error", snap, ok, err)
	}
}

func TestFROSTKeygenConfirmationSnapshotUsesPartyOrder(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	inbox := newFROSTKeygenConfirmationInbox(tss.NewPartySet(1, 2, 3))
	for _, id := range tss.NewPartySet(3, 1, 2) {
		confirmation, ok := shares[id].KeygenConfirmation(id)
		if !ok {
			t.Fatalf("missing confirmation for party %d", id)
		}
		inbox.confirmations[id] = confirmation
		inbox.chainCodes[id] = bytes.Clone(confirmation.ChainCode)
	}
	snap, ok, err := inbox.snapshot()
	if err != nil || !ok {
		t.Fatalf("confirmation snapshot: ok=%v err=%v", ok, err)
	}
	defer snap.Destroy()
	for i, id := range tss.NewPartySet(1, 2, 3) {
		if snap.confirmations[i].Sender != id {
			t.Fatalf("confirmation %d sender = %d, want %d", i, snap.confirmations[i].Sender, id)
		}
	}
}

func TestFROSTKeygenCommitRevealChainCodeVerification(t *testing.T) {
	t.Parallel()

	sessionID := frostPlanTestSession(0x66)
	chainCode := bytes.Repeat([]byte{0x42}, 32)
	commitment := bip32util.ChainCodeCommitment(frostChainCodeCommitLabel, sessionID, 2, chainCode)
	if err := verifyFROSTKeygenCommitRevealChainCode(sessionID, 2, chainCode, commitment); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(chainCode)
	tampered[0] ^= 1
	if err := verifyFROSTKeygenCommitRevealChainCode(sessionID, 2, tampered, commitment); err == nil {
		t.Fatal("tampered chain code reveal was accepted")
	}
}

func TestFROSTValidateKeygenConfirmationSetDoesNotMutateShare(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	local := shares[1]
	before, err := local.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	confirmations, err := local.orderedKeygenConfirmations()
	if err != nil {
		t.Fatal(err)
	}
	confirmations[1].TranscriptHash[0] ^= 1
	if err := validateKeygenConfirmationSetForShare(local, confirmations); err == nil {
		t.Fatal("tampered confirmation set was accepted")
	}
	after, err := local.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("confirmation validation mutated the key share")
	}
}
