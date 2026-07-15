package paillier

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
)

func TestGoldenProofPayloads(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		marshal   func(t *testing.T) []byte
		roundTrip func(t *testing.T, raw []byte)
	}{
		{
			name: "SecurityParams",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, DefaultSecurityParams())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinaryValue[SecurityParams])
			},
		},
		{
			name: "ModulusProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, seedModulusProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinary[ModulusProof])
			},
		},
		{
			name: "FactorProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, seedFactorProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinary[FactorProof])
			},
		},
		{
			name: "RingPedersenParams",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				raw, err := MarshalRingPedersenParams(seedRingPedersenParams())
				if err != nil {
					t.Fatal(err)
				}
				return raw
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				decoded, err := tss.DecodeBinary[RingPedersenParams](raw)
				if err != nil {
					t.Fatal(err)
				}
				again, err := MarshalRingPedersenParams(decoded)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(raw, again) {
					t.Fatal("Ring-Pedersen params did not remarshal deterministically")
				}
			},
		},
		{
			name: "RingPedersenProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, seedRingPedersenProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinary[RingPedersenProof])
			},
		},
		{
			name: "EncProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, seedEncProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinary[EncProof])
			},
		},
		{
			name: "AffGProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, seedAffGProof(t))
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinary[AffGProof])
			},
		},
		{
			name: "LogStarProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalBinary(t, seedLogStarProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertBinaryProofWireRoundTrip(t, raw, tss.DecodeBinary[LogStarProof])
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.marshal(t)
			testvectors.CheckHexGolden(t, "wire/v1/zk/"+tc.name+".golden", raw)
			tc.roundTrip(t, raw)
		})
	}
}

func seedFactorProof() *FactorProof {
	return &FactorProof{
		P: big.NewInt(2), Q: big.NewInt(3), A: big.NewInt(4), B: big.NewInt(5), T: big.NewInt(6),
		Sigma: big.NewInt(-7), Z1: big.NewInt(8), Z2: big.NewInt(-9), W1: big.NewInt(10),
		W2: big.NewInt(-11), V: big.NewInt(12), TranscriptHash: bytes.Repeat([]byte{0xfa}, 32),
	}
}

func seedRingPedersenParams() *RingPedersenParams {
	return &RingPedersenParams{
		N: big.NewInt(15),
		S: big.NewInt(2),
		T: big.NewInt(4),
	}
}

func assertBinaryProofWireRoundTrip[P binaryProof](t *testing.T, raw []byte, unmarshal func([]byte) (P, error)) {
	t.Helper()
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("proof did not remarshal deterministically")
	}
	if _, err := unmarshal(append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("proof accepted trailing byte")
	}
}
