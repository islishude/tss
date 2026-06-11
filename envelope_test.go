package tss

import (
	"testing"
)

func TestEnvelopeBinaryRoundTripAndTranscript(t *testing.T) {
	t.Parallel()
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "payload",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	// Recompute transcript hash from wire-decoded fields
	decoded.TranscriptHash = decoded.domainSeparatedHash()
	if err := ValidateEnvelopeBasic(decoded, "test", session, []PartyID{1, 2}); err != nil {
		t.Fatal(err)
	}
	// Zero out transcript hash and check failure
	decoded.TranscriptHash = [32]byte{}
	if err := ValidateEnvelopeBasic(decoded, "test", session, []PartyID{1, 2}); err == nil {
		t.Fatal("expected missing transcript hash rejection")
	}
	decoded.TranscriptHash = env.TranscriptHash
	decoded.Payload[0] ^= 1
	if err := ValidateEnvelopeBasic(decoded, "test", session, []PartyID{1, 2}); err == nil {
		t.Fatal("expected transcript mismatch")
	}
}

func TestEnvelopeUnmarshalRejectsNonCanonicalEncoding(t *testing.T) {
	t.Parallel()
	var decoded Envelope
	if err := decoded.UnmarshalBinary([]byte(`{"protocol":"test","version":1}`)); err == nil {
		t.Fatal("JSON envelope encoding accepted")
	}
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0)
	if err := decoded.UnmarshalBinary(raw); err == nil {
		t.Fatal("envelope with trailing bytes accepted")
	}
}
