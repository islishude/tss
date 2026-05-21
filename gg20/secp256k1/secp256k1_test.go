package secp256k1

import (
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
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

func TestThresholdECDSAPresignReuseRejected(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	presignSessions := map[tss.PartyID]*PresignSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := StartPresign(shares[id], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		presignSessions[id] = session
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if _, err := presignSessions[id].HandlePresignMessage(env); err != nil {
				t.Fatal(err)
			}
		}
	}
	presign, ok := presignSessions[1].Presign()
	if !ok {
		t.Fatal("presign not complete")
	}
	digest := sha256.Sum256([]byte("reuse"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartSignDigest(shares[1], presign, signID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartSignDigest(shares[1], presign, signID, digest[:]); err == nil {
		t.Fatal("expected presign reuse rejection")
	}
}

func TestThresholdECDSAKeyShareRoundTrip(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.PublicKey) != string(shares[1].PublicKey) {
		t.Fatal("public key mismatch after round trip")
	}
}

func secpKeygen(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	var pub []byte
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		if pub == nil {
			pub = share.PublicKey
		} else if string(pub) != string(share.PublicKey) {
			t.Fatal("group public key mismatch")
		}
		out[id] = share
	}
	return out
}
