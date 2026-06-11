package secp256k1

import (
	"bytes"
	"math/big"
	"path/filepath"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// TestFast_GoldenPresignMarshalBinary verifies deterministic wire encoding of
// a full Presign record including VerifyShares. No keygen is required.
func TestFast_GoldenPresignMarshalBinary(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "Presign.golden")
	checkGolden(t, golden, raw)

	// Round-trip: unmarshal → marshal must produce identical bytes.
	decoded, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := UnmarshalPresign(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

// TestFast_GoldenKeygenSharePayload verifies deterministic wire encoding of
// keygen share payloads. No keygen or crypto is required.
func TestFast_GoldenKeygenSharePayload(t *testing.T) {
	t.Parallel()
	payload := keygenSharePayload{Share: big.NewInt(1)}
	raw, err := marshalKeygenSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "KeygenSharePayload.golden")
	checkGolden(t, golden, raw)

	decoded, err := unmarshalKeygenSharePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalKeygenSharePayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalKeygenSharePayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

// TestFast_GoldenSignPartialPayload verifies deterministic wire encoding of
// sign partial payloads. No keygen or crypto is required.
func TestFast_GoldenSignPartialPayload(t *testing.T) {
	t.Parallel()
	payload := signPartialPayload{
		S:                   big.NewInt(1),
		PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
		PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
		DigestHash:          bytes.Repeat([]byte{0xcc}, 32),
		PartialEquationHash: bytes.Repeat([]byte{0xdd}, 32),
	}
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "SignPartialPayload.golden")
	checkGolden(t, golden, raw)

	decoded, err := unmarshalSignPartialPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalSignPartialPayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalSignPartialPayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

// TestFast_GoldenPresignRound3Payload verifies deterministic wire encoding of
// presign round 3 payloads. No keygen or crypto is required.
func TestFast_GoldenPresignRound3Payload(t *testing.T) {
	t.Parallel()
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(2))))
	proof := mustMinimalSignPrepProofForTest(t)
	payload := presignRound3Payload{
		Delta:    big.NewInt(42),
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proof,
	}
	raw, err := marshalPresignRound3Payload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "PresignRound3Payload.golden")
	checkGolden(t, golden, raw)

	decoded, err := unmarshalPresignRound3Payload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalPresignRound3Payload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalPresignRound3Payload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}
