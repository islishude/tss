package ed25519

import (
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// Online latency: interactive signing.

func BenchmarkFROSTSign2of3(b *testing.B) {
	shares := cachedFrostKeygen(b, 2, 3)
	signers := tss.NewPartySet(1, 2)
	message := sha256.Sum256([]byte("benchmark frost sign"))

	for b.Loop() {
		b.StopTimer()
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		sessions := make(map[tss.PartyID]*SignSession, len(signers))
		var messages []tss.Envelope
		for _, id := range signers {
			session, out, err := startFROSTSign(shares[id], sessionID, signers, message[:])
			if err != nil {
				b.Fatal(err)
			}
			sessions[id] = session
			messages = append(messages, out...)
		}
		for _, env := range messages {
			for _, id := range signers {
				if id == env.From {
					continue
				}
				_, err := sessions[id].HandleSignMessage(testutil.DeliverEnvelope(env))
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}
