package tss

import (
	"testing"
)

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
