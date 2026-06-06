package paillier

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenProofPayloads(t *testing.T) {
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
			checkPaillierGolden(t, filepath.Join("testdata", tc.name+".golden"), raw)
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

func checkPaillierGolden(t *testing.T, golden string, raw []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatalf("reading golden %s: %v (run with UPDATE_GOLDEN=1 to generate)", golden, err)
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		t.Errorf("golden mismatch:\n  got:  %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}
}
