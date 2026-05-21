package ed25519

import (
	stded25519 "crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/islishude/tss"
)

func TestFROSTSignScenarios(t *testing.T) {
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
			shares := frostKeygen(t, tc.threshold, tc.parties)
			selected := make([]*KeyShare, 0, len(tc.signers))
			for _, id := range tc.signers {
				selected = append(selected, shares[id])
			}
			pub, sig, err := Sign([]byte("hello frost"), selected)
			if err != nil {
				t.Fatal(err)
			}
			if !stded25519.Verify(stded25519.PublicKey(pub), []byte("hello frost"), sig) {
				t.Fatal("signature did not verify with crypto/ed25519")
			}
		})
	}
}

func TestFROSTKeyShareRoundTrip(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
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

func TestFROSTRejectsDuplicateCommitment(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandleSignMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandleSignMessage(out2[0]); err == nil {
		t.Fatal("expected duplicate commitment rejection")
	}
}

func TestFROSTBlamesBadPartial(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	sessions := map[tss.PartyID]*SignSession{}
	round1 := make([]tss.Envelope, 0)
	for _, id := range signers {
		s, out, err := StartSign(shares[id], sessionID, signers, []byte("msg"))
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = s
		round1 = append(round1, out[0])
	}
	round2 := make([]tss.Envelope, 0)
	for _, env := range round1 {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			out, err := sessions[id].HandleSignMessage(env)
			if err != nil {
				t.Fatal(err)
			}
			round2 = append(round2, out...)
		}
	}
	if len(round2) == 0 {
		t.Fatal("expected partial signatures")
	}
	var payload signPartialPayload
	if err := json.Unmarshal(round2[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Z[0] ^= 1
	mutated, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	round2[0].Payload = mutated
	round2[0] = round2[0].WithTranscriptHash()
	var delivered bool
	for _, id := range signers {
		if id == round2[0].From {
			continue
		}
		delivered = true
		if _, err := sessions[id].HandleSignMessage(round2[0]); err == nil {
			t.Fatal("expected bad partial rejection")
		}
	}
	if !delivered {
		t.Fatal("mutated partial was not delivered")
	}
}

func frostKeygen(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
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
