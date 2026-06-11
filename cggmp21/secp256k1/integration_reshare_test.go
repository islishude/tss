//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"math/big"
	"testing"
)

func TestThresholdECDSAReshareInvalidShareCarriesEvidence(t *testing.T) {
	runLimitedIntegration(t)

	shares := CachedKeygenShares(t, 2, 2, false)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	plan, err := NewResharePlan(shares[1], sessionID, parties, parties, 2)
	if err != nil {
		t.Fatal(err)
	}
	session, out1, err := StartReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	session2, out2, err := StartReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2.SetGuard(testCGGMP21Guard(2, tss.PartySet(shares[2].Parties), sessionID))
	if _, err := session.HandleReshareMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	dealer2Out, err := session2.HandleReshareMessage(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(dealer2Out) < 2 {
		t.Fatalf("dealer 2 emitted %d messages, want commitment and share", len(dealer2Out))
	}
	if _, err := session.HandleReshareMessage(testutil.DeliverEnvelope(dealer2Out[0])); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalReshareSharePayload(dealer2Out[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	badShare := new(big.Int).Set(payload.Share)
	badShare.Add(badShare, big.NewInt(1))
	badShare.Mod(badShare, secp.Order())
	if badShare.Sign() == 0 {
		badShare.SetInt64(1)
	}
	payload.Share = badShare
	dealer2Out[1].Payload, err = marshalReshareSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	dealer2Out[1] = dealer2Out[1].RecomputeTranscriptHash()
	_, err = session.HandleReshareMessage(testutil.DeliverEnvelope(dealer2Out[1]))
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSAReshareBuffersShareBeforeCommitments(t *testing.T) {
	runLimitedIntegration(t)

	shares := CachedKeygenShares(t, 2, 2, false)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	plan, err := NewResharePlan(shares[1], sessionID, parties, parties, 2)
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := StartReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session1.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	session2, out2, err := StartReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2.SetGuard(testCGGMP21Guard(2, tss.PartySet(shares[2].Parties), sessionID))
	dealer2Out, err := session2.HandleReshareMessage(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(dealer2Out) < 2 {
		t.Fatalf("dealer 2 emitted %d messages, want commitment and share", len(dealer2Out))
	}
	var commitment, share tss.Envelope
	for _, env := range dealer2Out {
		switch env.PayloadType {
		case payloadReshareDealerCommitments:
			commitment = env
		case payloadReshareShare:
			if env.To == 1 {
				share = env
			}
		}
	}
	if commitment.Payload == nil || share.Payload == nil {
		t.Fatal("missing dealer 2 commitment or share")
	}
	if _, err := session1.HandleReshareMessage(testutil.DeliverEnvelope(share)); err != nil {
		t.Fatalf("share before commitments should be buffered: %v", err)
	}
	if len(session1.pendingShares) != 1 {
		t.Fatalf("got %d pending shares, want 1", len(session1.pendingShares))
	}
	if _, err := session1.HandleReshareMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := session1.HandleReshareMessage(testutil.DeliverEnvelope(commitment)); err != nil {
		t.Fatal(err)
	}
	if len(session1.pendingShares) != 0 {
		t.Fatalf("got %d pending shares after commitment, want 0", len(session1.pendingShares))
	}
	if _, ok := session1.shares[2]; !ok {
		t.Fatal("pending share was not applied after commitment arrived")
	}
}

// TestThresholdECDSAReshareMembershipChange verifies that reshare preserves the
// group public key across add-party, remove-party, threshold-change, and
// disjoint-dealer-subset scenarios.
func TestThresholdECDSAReshareMembershipChange(t *testing.T) {
	runLimitedIntegration(t)

	oldShares := CachedKeygenShares(t, 2, 3, false)
	oldPub := oldShares[1].PublicKeyBytes()

	tests := []struct {
		name          string
		newParties    []tss.PartyID
		newThreshold  int
		dealerParties []tss.PartyID // nil means all old parties
		signers       []tss.PartyID
		removedParty  tss.PartyID // party expected to be removed (0 = none)
		assert        func(t *testing.T, newShares map[tss.PartyID]*KeyShare, sessions map[tss.PartyID]*ReshareSession)
	}{
		{
			name:         "add party 2-of-3 to 2-of-4",
			newParties:   []tss.PartyID{1, 2, 3, 4},
			newThreshold: 2,
			signers:      []tss.PartyID{2, 4},
		},
		{
			name:         "remove party 2-of-3 to 2-of-2",
			newParties:   []tss.PartyID{1, 3},
			newThreshold: 2,
			signers:      []tss.PartyID{1, 3},
			removedParty: 2,
		},
		{
			name:         "threshold increase 2-of-3 to 3-of-5",
			newParties:   []tss.PartyID{1, 2, 3, 4, 5},
			newThreshold: 3,
			signers:      []tss.PartyID{1, 4, 5},
		},
		{
			name:          "disjoint dealer subset 2-of-3 to 2-of-3",
			newParties:    []tss.PartyID{4, 5, 6},
			newThreshold:  2,
			dealerParties: []tss.PartyID{1, 3},
			signers:       []tss.PartyID{4, 6},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runLimitedIntegration(t)

			var newShares map[tss.PartyID]*KeyShare
			var sessions map[tss.PartyID]*ReshareSession

			if tc.dealerParties != nil {
				newShares, sessions = runCGGMP21ReshareWithDealers(t, oldShares, tc.dealerParties, tc.newParties, tc.newThreshold)
			} else {
				newShares, sessions = runCGGMP21Reshare(t, oldShares, tc.newParties, tc.newThreshold)
			}

			// Verify new share count matches new party count.
			if len(newShares) != len(tc.newParties) {
				t.Fatalf("got %d new shares, want %d", len(newShares), len(tc.newParties))
			}

			// Verify public key preserved for all new parties.
			for _, id := range tc.newParties {
				if !bytes.Equal(newShares[id].PublicKey, oldPub) {
					t.Fatalf("party %d public key changed after reshare", id)
				}
			}

			// Verify removed party is excluded.
			if tc.removedParty != 0 {
				if _, ok := newShares[tc.removedParty]; ok {
					t.Fatalf("removed party %d received a new key share", tc.removedParty)
				}
				if share, ok := sessions[tc.removedParty].KeyShare(); ok || share != nil {
					t.Fatalf("removed party %d session produced a key share", tc.removedParty)
				}
			}

			// Sign and verify with the selected signer subset.
			digest := sha256.Sum256([]byte("reshare " + tc.name))
			pub, sig, err := SignDigest(digest[:], collectShares(t, newShares, tc.signers))
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyDigest(pub, digest[:], sig) {
				t.Fatal("signature after reshare did not verify")
			}
			if !bytes.Equal(pub, oldPub) {
				t.Fatal("reshare changed group public key")
			}
		})
	}
}

// collectShares returns key shares for the given party IDs.
func collectShares(t *testing.T, shares map[tss.PartyID]*KeyShare, ids []tss.PartyID) []*KeyShare {
	t.Helper()
	out := make([]*KeyShare, 0, len(ids))
	for _, id := range ids {
		share, ok := shares[id]
		if !ok {
			t.Fatalf("party %d missing from new shares", id)
		}
		out = append(out, share)
	}
	return out
}
