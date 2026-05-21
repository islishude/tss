package secp256k1

import (
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
)

func BenchmarkPaillierKeygen2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := pai.GenerateKey(nil, DefaultPaillierBits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThresholdECDSAPresign2of3(b *testing.B) {
	shares := secpKeygen(b, 2, 3)
	signers := []tss.PartyID{1, 2}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secpPresign(b, shares, signers)
	}
}

func BenchmarkThresholdECDSAPresign3of5(b *testing.B) {
	shares := secpKeygen(b, 3, 5)
	signers := []tss.PartyID{1, 3, 5}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secpPresign(b, shares, signers)
	}
}

func BenchmarkThresholdECDSAOnlineSign2of3(b *testing.B) {
	shares := secpKeygen(b, 2, 3)
	signers := []tss.PartyID{1, 2}
	digest := sha256.Sum256([]byte("benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
				if _, err := signSessions[id].HandleSignMessage(env); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}
