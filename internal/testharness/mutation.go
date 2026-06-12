package testharness

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// MutateFn transforms an envelope for fault injection.
type MutateFn func(tss.Envelope) tss.Envelope

// WrongSession replaces the session ID with a deterministic but different value.
func WrongSession(env tss.Envelope) tss.Envelope {
	env.SessionID = testutil.MustSessionID(999)
	return env
}

// WrongProtocol replaces the protocol identifier.
func WrongProtocol(env tss.Envelope) tss.Envelope {
	env.Protocol = "wrong-protocol"
	return env
}

// WrongRound increments the round number.
func WrongRound(env tss.Envelope) tss.Envelope {
	env.Round++
	return env
}

// WrongSender replaces the sender with a different party ID.
func WrongSender(env tss.Envelope) tss.Envelope {
	env.From = tss.PartyID(uint32(env.From) + 99)
	return env
}

// WrongRecipient replaces the recipient.
func WrongRecipient(env tss.Envelope) tss.Envelope {
	env.To = tss.PartyID(99)
	return env
}

// CorruptPayload flips the first byte of the payload.
func CorruptPayload(env tss.Envelope) tss.Envelope {
	payload := make([]byte, len(env.Payload))
	copy(payload, env.Payload)
	if len(payload) > 0 {
		payload[0] ^= 0xff
	}
	env.Payload = payload
	return env
}

// SwapSenderWithRecipient swaps the From and To fields.
func SwapSenderWithRecipient(env tss.Envelope) tss.Envelope {
	env.From, env.To = env.To, env.From
	return env
}

// EquivocatePayload replaces the payload with a different one for the same
// (round, sender) slot, producing a different hash.
func EquivocatePayload(env tss.Envelope) tss.Envelope {
	h := sha256.Sum256(env.Payload)
	for i := range h {
		h[i] ^= 0x01
	}
	env.Payload = h[:]
	return env
}
