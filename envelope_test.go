package tss

import (
	"bytes"
	"encoding/hex"
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

func TestEnvelopeDigestStableAfterVersionFieldRemoval(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Protocol:    "test",
		SessionID:   SessionID{1, 2, 3},
		Round:       4,
		From:        5,
		To:          6,
		PayloadType: "payload",
		Payload:     []byte("body"),
	}
	got := env.Digest()
	const wantHex = "c7d9842684509cc7caa8c7de35922993e60f7adc5d25008e859cb9e15a782d48"
	if hex.EncodeToString(got[:]) != wantHex {
		t.Fatalf("envelope digest changed: got %x, want %s", got, wantHex)
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
	if version != envelopeWireVersion {
		t.Fatalf("wire version = %d, want %d", version, envelopeWireVersion)
	}
	if len(fields) != 7 {
		t.Fatalf("wire field count = %d, want 7", len(fields))
	}
	wantTags := []uint16{1, 2, 3, 4, 5, 6, 7}
	for i, field := range fields {
		if want := wantTags[i]; field.Tag != want {
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

func TestEnvelopeUnmarshalRejectsRetiredFieldsAndWrongFrameVersion(t *testing.T) {
	t.Parallel()

	session, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
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
	oldFields := []wire.Field{
		{Tag: 1, Value: fields[0].Value},
		{Tag: 2, Value: wire.Uint16(envelopeWireVersion)},
		{Tag: 3, Value: fields[1].Value},
		{Tag: 4, Value: fields[2].Value},
		{Tag: 5, Value: fields[3].Value},
		{Tag: 6, Value: fields[4].Value},
		{Tag: 7, Value: fields[5].Value},
		{Tag: 8, Value: fields[6].Value},
	}
	tests := []struct {
		name    string
		version uint16
		fields  []wire.Field
	}{
		{
			name:    "retired body layout",
			version: version,
			fields:  oldFields,
		},
		{
			name:    "transcript hash field",
			version: version,
			fields:  append(fields, wire.Field{Tag: 8, Value: digest[:]}),
		},
		{
			name:    "wrong frame version",
			version: envelopeWireVersion + 1,
			fields:  fields,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := wire.MarshalFields(tt.version, envelopeWireType, tt.fields)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Envelope
			if err := decoded.UnmarshalBinary(raw); err == nil {
				t.Fatal("accepted retired or wrong-version envelope")
			}
		})
	}
}
