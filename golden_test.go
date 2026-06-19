package tss

import (
	"bytes"
	"testing"

	"github.com/islishude/tss/internal/testvectors"
)

func TestGoldenEnvelope(t *testing.T) {
	t.Parallel()
	sessionID, err := SessionIDFromBytes(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test.v1",
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		To:          0,
		PayloadType: "test.payload",
		Payload:     []byte{0x01, 0x02, 0x03},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/envelope/Envelope.golden", raw)

	// Round-trip.
	var decoded Envelope
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}

	// Reject trailing byte.
	if err := (&Envelope{}).UnmarshalBinary(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenBlameEvidence(t *testing.T) {
	t.Parallel()
	sessionID, err := SessionIDFromBytes(bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewBlameEvidence(Envelope{
		Protocol:    "test.v1",
		SessionID:   sessionID,
		Round:       2,
		From:        1,
		To:          2,
		PayloadType: "test.payload",
		Payload:     []byte{0x01, 0x02, 0x03},
	}, EvidenceKindSignPartial, "invalid partial", []EvidenceField{
		{Key: "public", Value: []byte{0x04, 0x05}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/tss/BlameEvidence.golden", raw)
}

func TestGoldenSigningContext(t *testing.T) {
	t.Parallel()
	context := testSigningContext()
	raw, err := context.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/tss/SigningContext.golden", raw)
}

func TestGoldenBroadcastAck(t *testing.T) {
	t.Parallel()
	env := goldenBroadcastEnvelope(t)
	ack := BroadcastAck{
		Party:          1,
		PayloadHash:    PayloadHashFromEnvelope(env),
		EnvelopeDigest: env.Digest(),
		Signature:      []byte{1, 2, 3},
	}
	raw, err := ack.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/tss/BroadcastAck.golden", raw)
}

func TestGoldenBroadcastCertificate(t *testing.T) {
	t.Parallel()
	env := goldenBroadcastEnvelope(t)
	ack1 := BroadcastAck{
		Party:          1,
		PayloadHash:    PayloadHashFromEnvelope(env),
		EnvelopeDigest: env.Digest(),
		Signature:      []byte{1},
	}
	ack2 := ack1.Clone()
	ack2.Party = 2
	ack2.Signature = []byte{2}
	cert, err := NewBroadcastCertificate(env, PartySet{1, 2}, []BroadcastAck{ack1, ack2})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/tss/BroadcastCertificate.golden", raw)
}

func goldenBroadcastEnvelope(t *testing.T) Envelope {
	t.Helper()
	sessionID, err := SessionIDFromBytes(bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return testBroadcastEnvelope(t, sessionID)
}
