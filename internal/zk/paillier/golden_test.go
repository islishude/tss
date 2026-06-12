package paillier

import (
	"bytes"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/islishude/tss/internal/testutil"
)

func TestGoldenProofPayloads(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		marshal   func(t *testing.T) []byte
		roundTrip func(t *testing.T, raw []byte)
	}{
		{
			name: "ModulusProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalProof(t, seedModulusProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertProofWireRoundTrip(t, raw, UnmarshalModulusProof, Marshal)
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
				decoded, err := UnmarshalRingPedersenParams(raw)
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
				return mustMarshalProof(t, seedRingPedersenProof())
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertProofWireRoundTrip(t, raw, UnmarshalRingPedersenProof, Marshal)
			},
		},
		{
			name: "EncryptionProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalProof(t, seedEncryptionProof(t))
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertProofWireRoundTrip(t, raw, UnmarshalEncryptionProof, Marshal)
			},
		},
		{
			name: "MTAResponseProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalProof(t, seedMTAResponseProof(t))
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertProofWireRoundTrip(t, raw, UnmarshalMTAResponseProof, Marshal)
			},
		},
		{
			name: "LogProof",
			marshal: func(t *testing.T) []byte {
				t.Helper()
				return mustMarshalProof(t, seedLogProof(t))
			},
			roundTrip: func(t *testing.T, raw []byte) {
				t.Helper()
				assertProofWireRoundTrip(t, raw, UnmarshalLogProof, Marshal)
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
				assertBinaryProofWireRoundTrip(t, raw, UnmarshalEncProof)
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
				assertBinaryProofWireRoundTrip(t, raw, UnmarshalAffGProof)
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
				assertBinaryProofWireRoundTrip(t, raw, UnmarshalLogStarProof)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.marshal(t)
			testutil.CheckGolden(t, filepath.Join("..", "..", "testvectors", "wire", "v1", "zk", tc.name+".golden"), raw)
			tc.roundTrip(t, raw)
		})
	}
}

func seedRingPedersenParams() *RingPedersenParams {
	return &RingPedersenParams{
		N: big.NewInt(15),
		S: big.NewInt(2),
		T: big.NewInt(4),
	}
}

func assertProofWireRoundTrip[P any](t *testing.T, raw []byte, unmarshal func([]byte) (P, error), marshal func(any) ([]byte, error)) {
	t.Helper()
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("proof did not remarshal deterministically")
	}
	if _, err := unmarshal(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("proof accepted trailing byte")
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
	if _, err := unmarshal(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("proof accepted trailing byte")
	}
}
