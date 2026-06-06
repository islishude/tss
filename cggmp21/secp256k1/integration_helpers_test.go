//go:build integration || vectorgen

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
)

func deliverPresignMessagesTo(t testing.TB, session *PresignSession, receiver tss.PartyID, messages []tss.Envelope) []tss.Envelope {
	t.Helper()
	var out []tss.Envelope
	for _, env := range messages {
		if env.From == receiver || (env.To != 0 && env.To != receiver) {
			continue
		}
		next, err := session.HandlePresignMessage(env)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, next...)
	}
	return out
}

func presignRound1ProofEnvelopeFor(t testing.TB, messages []tss.Envelope, to tss.PartyID) tss.Envelope {
	t.Helper()
	for _, env := range messages {
		if env.PayloadType == payloadPresignRound1Proof && env.To == to {
			return env
		}
	}
	t.Fatalf("missing presign round1 proof envelope to %d", to)
	return tss.Envelope{}
}
