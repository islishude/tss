package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

func testLimits() Limits {
	limits := DefaultLimits()
	limits.Threshold = tss.ThresholdLimits{
		MaxParties:              8,
		MaxThreshold:            8,
		MaxSigners:              8,
		MinProductionThreshold:  1,
		AllowOneOfOne:           true,
		AllowOversizedSignerSet: true,
	}
	limits.Paillier = PaillierLimits{
		MaxModulusBits:       8192,
		MaxPublicKeyBytes:    4096,
		MaxPrivateKeyBytes:   8192,
		MaxCiphertextBytes:   4096,
		MaxProofBytes:        512 << 10,
		MaxRingPedersenBytes: 16384,
		MaxMTAResponseBytes:  512 << 10,
	}
	limits.ZK.MaxProofBytes = 512 << 10
	limits.SignPrep.MaxProofBytes = 512 << 10
	return limits
}

func testSecurityParams() SecurityParams {
	return SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
}

func testSecretScalar(t testing.TB, v int64) *secret.Scalar {
	t.Helper()
	if v <= 0 {
		t.Fatalf("test secret scalar must be positive: %d", v)
	}
	s, err := secpSecretScalarFromScalar(secp.ScalarFromUint64(uint64(v)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unmarshalKeygenCommitmentsPayload(in []byte) (keygenCommitmentsPayload, error) {
	return tss.DecodeBinaryValueWithLimits[keygenCommitmentsPayload](in, testLimits())
}

func unmarshalKeygenSharePayload(in []byte) (keygenSharePayload, error) {
	return tss.DecodeBinaryValueWithLimits[keygenSharePayload](in, testLimits())
}

func unmarshalPresignRound1Payload(in []byte) (presignRound1Payload, error) {
	return tss.DecodeBinaryValueWithLimits[presignRound1Payload](in, testLimits())
}

func marshalPresignRound1ProofPayload(p presignRound1ProofPayload) ([]byte, error) {
	return p.MarshalBinaryWithLimits(testLimits())
}

func unmarshalPresignRound1ProofPayload(in []byte) (presignRound1ProofPayload, error) {
	return tss.DecodeBinaryValueWithLimits[presignRound1ProofPayload](in, testLimits())
}

func marshalPresignRound2Payload(p presignRound2Payload) ([]byte, error) {
	return p.MarshalBinaryWithLimits(testLimits())
}

func unmarshalPresignRound2Payload(in []byte) (presignRound2Payload, error) {
	return tss.DecodeBinaryValueWithLimits[presignRound2Payload](in, testLimits())
}

func marshalPresignRound3Payload(p presignRound3Payload) ([]byte, error) {
	return p.MarshalBinaryWithLimits(testLimits())
}

func unmarshalPresignRound3Payload(in []byte) (presignRound3Payload, error) {
	return tss.DecodeBinaryValueWithLimits[presignRound3Payload](in, testLimits())
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	return p.MarshalBinaryWithLimits(testLimits())
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	return tss.DecodeBinaryValueWithLimits[signPartialPayload](in, testLimits())
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	return p.MarshalBinaryWithLimits(testLimits())
}

func unmarshalReshareSharePayload(in []byte) (reshareSharePayload, error) {
	return tss.DecodeBinaryValueWithLimits[reshareSharePayload](in, testLimits())
}

func unmarshalRefreshCommitmentsPayload(in []byte) (refreshCommitmentsPayload, error) {
	return tss.DecodeBinaryValueWithLimits[refreshCommitmentsPayload](in, testLimits())
}

func unmarshalRefreshSharePayload(in []byte) (refreshSharePayload, error) {
	return tss.DecodeBinaryValueWithLimits[refreshSharePayload](in, testLimits())
}
