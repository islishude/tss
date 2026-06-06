//go:build integration || vectorgen

package secp256k1

import (
	"crypto/sha256"
	"github.com/islishude/tss"
	"testing"
)

func TestThresholdECDSASignScenarios(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int
		parties   int
		signers   []tss.PartyID
	}{
		{name: "1-of-1", threshold: 1, parties: 1, signers: []tss.PartyID{1}},
		{name: "2-of-3", threshold: 2, parties: 3, signers: []tss.PartyID{1, 3}},
		{name: "3-of-5", threshold: 3, parties: 5, signers: []tss.PartyID{1, 3, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := secpKeygen(t, tc.threshold, tc.parties)
			selected := make([]*KeyShare, 0, len(tc.signers))
			for _, id := range tc.signers {
				selected = append(selected, shares[id])
			}
			digest := sha256.Sum256([]byte("hello secp256k1"))
			pub, sig, err := SignDigest(digest[:], selected)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyDigest(pub, digest[:], sig) {
				t.Fatal("signature did not verify")
			}
		})
	}
}

func TestThresholdECDSASignerSubsets(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	for _, signers := range [][]tss.PartyID{{1, 2}, {1, 3}, {2, 3}} {
		selected := make([]*KeyShare, 0, len(signers))
		for _, id := range signers {
			selected = append(selected, shares[id])
		}
		digest := sha256.Sum256([]byte("subset"))
		pub, sig, err := SignDigest(digest[:], selected)
		if err != nil {
			t.Fatalf("signers %v: %v", signers, err)
		}
		if !VerifyDigest(pub, digest[:], sig) {
			t.Fatalf("signers %v: signature did not verify", signers)
		}
	}
}

func TestThresholdECDSATamperedOnlinePartialFails(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	digest := sha256.Sum256([]byte("online tamper"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[tss.PartyID]*SignSession{}
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSignDigest(shares[id], presigns[id], signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}
	payload, err := unmarshalSignPartialPayload(messages[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.S = scalarBytes(bigOne())
	mutated, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	messages[0].Payload = mutated
	messages[0] = messages[0].WithTranscriptHash()
	delivered := false
	for _, id := range signers {
		if id == messages[0].From {
			continue
		}
		delivered = true
		if _, err := sessions[id].HandleSignMessage(messages[0]); err == nil {
			t.Fatal("expected tampered partial rejection")
		} else {
			_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[id], signers, presigns[id]))
		}
	}
	if !delivered {
		t.Fatal("tampered partial was not delivered")
	}
}
