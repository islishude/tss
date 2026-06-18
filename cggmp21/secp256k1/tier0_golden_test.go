package secp256k1

import (
	"bytes"
	"math/big"
	"path/filepath"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

// TestFast_GoldenPresignMarshalBinary verifies deterministic wire encoding of
// a full Presign record including VerifyShares. No keygen is required.
func TestFast_GoldenPresignMarshalBinary(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "Presign.fast.golden")
	testutil.CheckGolden(t, golden, raw)

	// Round-trip: unmarshal → marshal must produce identical bytes.
	decoded, err := UnmarshalPresignWithLimits(raw, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := UnmarshalPresignWithLimits(append(raw, 0), testLimits()); err == nil {
		t.Error("accepted trailing byte")
	}
}

// TestFast_GoldenSignVerifyShare verifies the standalone verification-share
// wire contract used by the Presign VerifyShares record list.
func TestFast_GoldenSignVerifyShare(t *testing.T) {
	t.Parallel()
	share := minimalCGGMP21Presign(t).VerifyShares()[0]
	raw, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "SignVerifyShare.golden")
	testutil.CheckGolden(t, golden, raw)

	var decoded SignVerifyShare
	if err := decoded.UnmarshalBinaryWithLimits(raw, testLimits()); err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if err := decoded.UnmarshalBinaryWithLimits(append(raw, 0), testLimits()); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestFast_GoldenVerificationShare(t *testing.T) {
	t.Parallel()
	share := testVerificationShare(t)
	raw, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testutil.CheckGolden(t, filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "VerificationShare.golden"), raw)
}

func TestFast_GoldenPaillierPublicShare(t *testing.T) {
	t.Parallel()
	share := testPaillierPublicShare(t)
	raw, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testutil.CheckGolden(t, filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "PaillierPublicShare.golden"), raw)
}

func TestFast_GoldenRingPedersenPublicShare(t *testing.T) {
	t.Parallel()
	share := testRingPedersenPublicShare(t)
	raw, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testutil.CheckGolden(t, filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "RingPedersenPublicShare.golden"), raw)
}

// TestFast_GoldenKeygenSharePayload verifies deterministic wire encoding of
// keygen share payloads. No keygen or crypto is required.
func TestFast_GoldenKeygenSharePayload(t *testing.T) {
	t.Parallel()
	payload := keygenSharePayload{Share: testSecretScalar(t, 1), PlanHash: bytes.Repeat([]byte{0x90}, 32)}
	raw, err := marshalKeygenSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "KeygenSharePayload.golden")
	testutil.CheckGolden(t, golden, raw)

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

// TestFast_GoldenRefreshSharePayload verifies deterministic wire encoding of
// refresh share payloads. No refresh protocol run is required.
func TestFast_GoldenRefreshSharePayload(t *testing.T) {
	t.Parallel()
	payload := refreshSharePayload{Share: testSecretScalar(t, 2), PlanHash: bytes.Repeat([]byte{0x91}, 32)}
	raw, err := marshalRefreshSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "RefreshSharePayload.golden")
	testutil.CheckGolden(t, golden, raw)

	decoded, err := unmarshalRefreshSharePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalRefreshSharePayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalRefreshSharePayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

// TestFast_GoldenReshareSharePayload verifies deterministic wire encoding of
// reshare dealer-to-receiver share payloads.
func TestFast_GoldenReshareSharePayload(t *testing.T) {
	t.Parallel()
	payload := reshareSharePayload{
		Dealer:               1,
		Receiver:             2,
		Share:                testSecretScalar(t, 3),
		DealerCommitmentHash: bytes.Repeat([]byte{0x92}, 32),
		PlanHash:             bytes.Repeat([]byte{0x93}, 32),
	}
	raw, err := marshalReshareSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "ReshareSharePayload.golden")
	testutil.CheckGolden(t, golden, raw)

	decoded, err := unmarshalReshareSharePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalReshareSharePayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalReshareSharePayload(append(raw, 0)); err == nil {
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
		PlanHash:            bytes.Repeat([]byte{0xde}, 32),
	}
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "SignPartialPayload.golden")
	testutil.CheckGolden(t, golden, raw)

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

// TestFast_GoldenSignAttemptRecord verifies the durable attempt/outbox wire
// contract without running protocol setup.
func TestFast_GoldenSignAttemptRecord(t *testing.T) {
	t.Parallel()
	record := testSignAttemptRecord(t, 0x77)
	raw, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "SignAttemptRecord.golden")
	testutil.CheckGolden(t, golden, raw)

	decoded, err := UnmarshalSignAttemptRecord(raw)
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
	if _, err := UnmarshalSignAttemptRecord(append(raw, 0)); err == nil {
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
		PlanHash: bytes.Repeat([]byte{0x91}, 32),
	}
	raw, err := marshalPresignRound3Payload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "PresignRound3Payload.golden")
	testutil.CheckGolden(t, golden, raw)

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
