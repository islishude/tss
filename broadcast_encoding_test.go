package tss

import (
	"bytes"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestBroadcastAckCanonicalBinaryEncoding(t *testing.T) {
	t.Parallel()
	env := testBroadcastEnvelope(t, testSessionID(t))
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
	var decoded BroadcastAck
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if decoded.Party != ack.Party ||
		decoded.PayloadHash != ack.PayloadHash ||
		decoded.EnvelopeDigest != ack.EnvelopeDigest ||
		!bytes.Equal(decoded.Signature, ack.Signature) {
		t.Fatal("broadcast ack changed after round trip")
	}
	if err := decoded.UnmarshalBinary(append(raw, 0)); err == nil {
		t.Fatal("broadcast ack accepted trailing byte")
	}

	mutated, err := wire.MarshalFields(Version, broadcastAckWireType, []wire.Field{
		{Tag: 1, Value: wire.Uint32(BroadcastPartyId)},
		{Tag: 2, Value: ack.PayloadHash[:]},
		{Tag: 3, Value: ack.EnvelopeDigest[:]},
		{Tag: 4, Value: ack.Signature},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.UnmarshalBinary(mutated); err == nil {
		t.Fatal("broadcast ack accepted zero party")
	}
}

func TestBroadcastCertificateCanonicalBinaryEncoding(t *testing.T) {
	t.Parallel()
	env := testBroadcastEnvelope(t, testSessionID(t))
	ack1 := BroadcastAck{
		Party:          1,
		PayloadHash:    PayloadHashFromEnvelope(env),
		EnvelopeDigest: env.Digest(),
		Signature:      []byte{1},
	}
	ack2 := ack1.Clone()
	ack2.Party = 2
	ack2.Signature = []byte{2}
	cert, err := NewBroadcastCertificate(env, PartySet{2, 1}, []BroadcastAck{ack2, ack1})
	if err != nil {
		t.Fatal(err)
	}

	raw1, err := cert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := cert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("broadcast certificate encoding is not deterministic")
	}
	if !slicesEqual(cert.Recipients, PartySet{1, 2}) ||
		cert.Acks[0].Party != 1 || cert.Acks[1].Party != 2 {
		t.Fatal("broadcast certificate was not canonicalized")
	}

	decoded, err := UnmarshalBroadcastCertificate(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.VerifyStructure(env, PartySet{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := decoded.UnmarshalBinary(append(raw1, 0)); err == nil {
		t.Fatal("broadcast certificate accepted trailing byte")
	}
}

func slicesEqual(a, b PartySet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
