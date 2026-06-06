//go:build integration

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/islishude/tss"
)

// TestCGGMP21ConcurrentKeygenWithMutex verifies keygen works correctly when
// each session is protected by its own mutex for concurrent message delivery.
// Session APIs are not internally synchronized — callers must serialize access.
func TestCGGMP21ConcurrentKeygenWithMutex(t *testing.T) {
	n := 5
	threshold := 3
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	type lockedSession struct {
		*KeygenSession
		mu sync.Mutex
	}
	sessions := make(map[tss.PartyID]*lockedSession, n)
	var allMessages []tss.Envelope
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = &lockedSession{KeygenSession: kg}
		allMessages = append(allMessages, out...)
	}
	deliverWave := func(messages []tss.Envelope) []tss.Envelope {
		t.Helper()
		var wg sync.WaitGroup
		var producedMu sync.Mutex
		var produced []tss.Envelope
		for _, env := range messages {
			wg.Add(1)
			go func(env tss.Envelope) {
				defer wg.Done()
				for _, id := range parties {
					if id == env.From || (env.To != 0 && env.To != id) {
						continue
					}
					s := sessions[id]
					s.mu.Lock()
					out, err := s.HandleKeygenMessage(env)
					s.mu.Unlock()
					if err != nil {
						t.Errorf("concurrent keygen delivery from %d to %d: %v", env.From, id, err)
						continue
					}
					producedMu.Lock()
					produced = append(produced, out...)
					producedMu.Unlock()
				}
			}(env)
		}
		wg.Wait()
		return produced
	}
	for wave := allMessages; len(wave) > 0; wave = deliverWave(wave) {
	}
	var pub []byte
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d after concurrent delivery", id)
		}
		if pub == nil {
			pub = share.PublicKey
		} else if string(pub) != string(share.PublicKey) {
			t.Fatal("group public key mismatch after concurrent keygen")
		}
	}
}

// TestCGGMP21AdversarialDeliveryOrder verifies that presign and sign messages
// delivered in arbitrary order within each round still produce valid signatures.
// Messages are shuffled round-by-round since later rounds depend on earlier ones.
func TestCGGMP21AdversarialDeliveryOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 42)) //nolint:gosec // deterministic RNG for reproducible test shuffles
	shares := secpKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 3}

	for range 10 {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		sess := make(map[tss.PartyID]*PresignSession, len(signers))
		var round1, round2, round3 []tss.Envelope
		for _, id := range signers {
			s, out, err := StartPresign(shares[id], sessionID, signers)
			if err != nil {
				t.Fatal(err)
			}
			sess[id] = s
			for _, env := range out {
				switch env.Round {
				case 1:
					round1 = append(round1, env)
				case 2:
					round2 = append(round2, env)
				case 3:
					round3 = append(round3, env)
				}
			}
		}
		// Shuffle within each round and process.
		processPresignRound := func(msgs []tss.Envelope) []tss.Envelope {
			rng.Shuffle(len(msgs), func(i, j int) { msgs[i], msgs[j] = msgs[j], msgs[i] })
			var nextRound []tss.Envelope
			for _, env := range msgs {
				for _, id := range signers {
					if id == env.From {
						continue
					}
					if env.To != 0 && env.To != id {
						continue
					}
					out, _ := sess[id].HandlePresignMessage(env)
					nextRound = append(nextRound, out...)
				}
			}
			return nextRound
		}
		round2 = append(round2, processPresignRound(round1)...)
		round3 = append(round3, processPresignRound(round2)...)
		processPresignRound(round3)

		for _, id := range signers {
			if _, ok := sess[id].Presign(); !ok {
				t.Fatalf("presign not complete for %d under shuffled delivery", id)
			}
		}

		// Verify signing still produces a valid signature.
		digest := sha256.Sum256([]byte("adversarial scheduler"))
		signID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		signSessions := make(map[tss.PartyID]*SignSession, len(signers))
		var sigMessages []tss.Envelope
		var refSig *Signature
		for _, id := range signers {
			p, _ := sess[id].Presign()
			s, out, err := StartSignDigest(shares[id], p, signID, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			signSessions[id] = s
			sigMessages = append(sigMessages, out...)
		}
		rng.Shuffle(len(sigMessages), func(i, j int) { sigMessages[i], sigMessages[j] = sigMessages[j], sigMessages[i] })
		for _, env := range sigMessages {
			for _, id := range signers {
				if id == env.From {
					continue
				}
				_, _ = signSessions[id].HandleSignMessage(env)
			}
		}
		for _, id := range signers {
			sig, ok := signSessions[id].Signature()
			if !ok {
				t.Fatalf("signing did not complete for %d after shuffled delivery", id)
			}
			if refSig == nil {
				refSig = sig
			} else if !bytes.Equal(refSig.R, sig.R) || !bytes.Equal(refSig.S, sig.S) {
				t.Fatal("signature mismatch after adversarial delivery")
			}
		}
	}
}
