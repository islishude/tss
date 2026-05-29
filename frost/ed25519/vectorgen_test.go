//go:build vectorgen

package ed25519

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateVectors(t *testing.T) {
	generateFROSTVectors(t, filepath.Join("testdata", "frost_ed25519_vectors.json"))
}

func generateFROSTVectors(t *testing.T, path string) {
	t.Helper()
	vectors := []frostTestVector{
		{
			Description: "FROST Ed25519 1-of-1 keygen and signing",
			Threshold:   1,
			N:           1,
			Parties:     []int{1},
			Seed:        "0000000000000000000000000000000000000000000000000000000000000001",
			Message:     hex.EncodeToString([]byte("FROST Ed25519 test message")),
			Signers:     []int{1},
		},
		{
			Description: "FROST Ed25519 2-of-3 keygen and signing",
			Threshold:   2,
			N:           3,
			Parties:     []int{1, 2, 3},
			Seed:        "0000000000000000000000000000000000000000000000000000000000000002",
			Message:     hex.EncodeToString([]byte("FROST 2-of-3 test message")),
			Signers:     []int{1, 2},
		},
	}
	for i := range vectors {
		v := &vectors[i]
		shares := frostVectorKeygen(t, v.Seed, v.Threshold, v.N)
		v.GroupPublicKey = hex.EncodeToString(shares[0].PublicKey)
		for _, s := range shares {
			raw, err := s.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			v.KeygenShares = append(v.KeygenShares, hex.EncodeToString(raw))
		}
		msg, err := hex.DecodeString(v.Message)
		if err != nil {
			t.Fatal(err)
		}
		signerCount := len(v.Signers)
		signerShares := make([]*KeyShare, signerCount)
		for j, pid := range v.Signers {
			signerShares[j] = shares[pid-1]
		}
		_, sig, err := Sign(msg, signerShares)
		if err != nil {
			t.Fatal(err)
		}
		v.Signature = hex.EncodeToString(sig)
	}
	raw, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}
