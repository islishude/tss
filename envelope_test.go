package tss

import (
	"bytes"
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

func TestEnvelopeDomainSeparatedHashBindsEveryField(t *testing.T) {
	t.Parallel()

	session, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	base := Envelope{
		Protocol:    "test",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "payload",
		Payload:     []byte("body"),
	}
	baseHash := base.domainSeparatedHash()

	tests := []struct {
		name   string
		mutate func(*Envelope)
	}{
		{name: "protocol", mutate: func(e *Envelope) { e.Protocol = "other" }},
		{name: "version", mutate: func(e *Envelope) { e.Version++ }},
		{name: "session", mutate: func(e *Envelope) { e.SessionID[0] ^= 1 }},
		{name: "round", mutate: func(e *Envelope) { e.Round++ }},
		{name: "from", mutate: func(e *Envelope) { e.From++ }},
		{name: "to", mutate: func(e *Envelope) { e.To++ }},
		{name: "payload type", mutate: func(e *Envelope) { e.PayloadType = "other" }},
		{name: "payload", mutate: func(e *Envelope) { e.Payload = []byte("other") }},
	}
	for _, tt := range tests {
		mutated := base.Clone()
		tt.mutate(&mutated)
		if got := mutated.domainSeparatedHash(); got == baseHash {
			t.Errorf("%s change did not change transcript hash", tt.name)
		}
	}
}
