//go:build integration

package secp256k1

import (
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// Online latency: interactive signing path.

func BenchmarkCGGMP21OnlineSign2of3(b *testing.B) {
	shares := CachedKeygenShares(b, 2, 3)
	signers := tss.NewPartySet(1, 2)
	digest := sha256.Sum256([]byte("benchmark"))

	for b.Loop() {
		b.StopTimer()
		presigns := secpPresign(b, shares, signers)
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		signSessions := map[tss.PartyID]*SignSession{}
		messages := make([]tss.Envelope, 0, len(signers))
		for _, id := range signers {
			session, out, err := StartSignDigest(shares[id], presigns[id], sessionID, digest[:])
			if err != nil {
				b.Fatal(err)
			}
			signSessions[id] = session
			messages = append(messages, out...)
		}
		for _, env := range messages {
			for _, id := range signers {
				if id == env.From {
					continue
				}
				if _, err := signSessions[id].HandleSignMessage(testutil.DeliverEnvelope(env)); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}

func BenchmarkCGGMP21OnlineSign3of5(b *testing.B) {
	shares := CachedKeygenShares(b, 3, 5)
	signers := tss.NewPartySet(1, 3, 5)
	digest := sha256.Sum256([]byte("benchmark 3of5"))

	for b.Loop() {
		b.StopTimer()
		presigns := secpPresign(b, shares, signers)
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		signSessions := map[tss.PartyID]*SignSession{}
		messages := make([]tss.Envelope, 0, len(signers))
		for _, id := range signers {
			session, out, err := StartSignDigest(shares[id], presigns[id], sessionID, digest[:])
			if err != nil {
				b.Fatal(err)
			}
			signSessions[id] = session
			messages = append(messages, out...)
		}
		for _, env := range messages {
			for _, id := range signers {
				if id == env.From {
					continue
				}
				if _, err := signSessions[id].HandleSignMessage(testutil.DeliverEnvelope(env)); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}
