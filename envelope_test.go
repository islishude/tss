package tss

import (
	"bytes"
	"testing"

	"github.com/islishude/tss/internal/wire"
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

func TestEnvelopeDigestBindsEveryField(t *testing.T) {
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
	baseDigest := base.Digest()

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
		if got := mutated.Digest(); got == baseDigest {
			t.Errorf("%s change did not change envelope digest", tt.name)
		}
	}
}

func TestEnvelopeDigestIsComputedOutsideWireSchema(t *testing.T) {
	t.Parallel()

	session, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x22}, 32)))
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
		Payload:     []byte("body"),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := wire.UnmarshalFields(raw, envelopeWireType)
	if err != nil {
		t.Fatal(err)
	}
	if version != Version {
		t.Fatalf("wire version = %d, want %d", version, Version)
	}
	if len(fields) != 8 {
		t.Fatalf("wire field count = %d, want 8", len(fields))
	}
	for i, field := range fields {
		if want := uint16(i + 1); field.Tag != want {
			t.Fatalf("wire field %d tag = %d, want %d", i, field.Tag, want)
		}
	}

	var decoded Envelope
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if got, want := decoded.Digest(), env.Digest(); got != want {
		t.Fatal("unmarshal changed the envelope digest")
	}
}

func TestEnvelopeUnmarshalRejectsRetiredTranscriptHashField(t *testing.T) {
	t.Parallel()

	session, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)))
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
		Payload:     []byte("body"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := wire.UnmarshalFields(raw, envelopeWireType)
	if err != nil {
		t.Fatal(err)
	}
	digest := env.Digest()
	fields = append(fields, wire.Field{Tag: 9, Value: digest[:]})
	retired, err := wire.MarshalFields(version, envelopeWireType, fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Envelope
	if err := decoded.UnmarshalBinary(retired); err == nil {
		t.Fatal("accepted retired envelope transcript hash field")
	}
}
