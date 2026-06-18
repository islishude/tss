package tss

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenEnvelope(t *testing.T) {
	t.Parallel()
	sessionID, err := SessionIDFromBytes(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test.v1",
		Version:     Version,
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

	golden := filepath.Join("internal", "testvectors", "wire", "v1", "envelope", "Envelope.golden")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}

	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatalf("reading golden file: %v (run with UPDATE_GOLDEN=1 to generate)", err)
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		t.Errorf("golden mismatch:\n  got: %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}

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

func TestGoldenSigningContext(t *testing.T) {
	t.Parallel()
	context := testSigningContext()
	raw, err := context.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	checkRootGolden(t, filepath.Join("internal", "testvectors", "wire", "v1", "tss", "SigningContext.golden"), raw)
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
	checkRootGolden(t, filepath.Join("internal", "testvectors", "wire", "v1", "tss", "BroadcastAck.golden"), raw)
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
	checkRootGolden(t, filepath.Join("internal", "testvectors", "wire", "v1", "tss", "BroadcastCertificate.golden"), raw)
}

func goldenBroadcastEnvelope(t *testing.T) Envelope {
	t.Helper()
	sessionID, err := SessionIDFromBytes(bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return testBroadcastEnvelope(t, sessionID)
}

func checkRootGolden(t testing.TB, golden string, raw []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantHex, err := os.ReadFile(golden) //nolint:gosec // fixed test-vector path
	if err != nil {
		t.Fatalf("reading golden file: %v (run with UPDATE_GOLDEN=1 to generate)", err)
	}
	if gotHex := hex.EncodeToString(raw); gotHex != string(bytes.TrimSpace(wantHex)) {
		t.Fatalf("golden mismatch:\n  got: %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}
}
