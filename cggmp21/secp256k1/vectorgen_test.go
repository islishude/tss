//go:build vectorgen

package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
)

func TestGenerateVectors(t *testing.T) {
	generateAndSaveCGGMP21Vectors(t, filepath.Join("..", "..", "internal", "testvectors", "protocol", "cggmp21-secp256k1", "cggmp21_secp256k1_vectors.json"))
}

func generateAndSaveCGGMP21Vectors(t *testing.T, path string) {
	t.Helper()
	vectors := []cggmp21TestVector{
		{
			Description: "CGGMP21 secp256k1 1-of-1 keygen",
			Threshold:   1, N: 1, Parties: []int{1},
			Seed:   "0000000000000000000000000000000000000000000000000000000000000003",
			Digest: hex.EncodeToString(hashBytes([]byte("CGGMP21 test digest"))),
		},
		{
			Description: "CGGMP21 secp256k1 2-of-3 keygen",
			Threshold:   2, N: 3, Parties: []int{1, 2, 3},
			Seed:   "0000000000000000000000000000000000000000000000000000000000000004",
			Digest: hex.EncodeToString(hashBytes([]byte("CGGMP21 2-of-3 test digest"))),
		},
	}
	for i := range vectors {
		v := &vectors[i]
		shares := secpKeygen(t, v.Threshold, v.N)
		pk1 := shares[tss.PartyID(v.Parties[0])]
		v.GroupPublicKey = hex.EncodeToString(pk1.PublicKey)
		for _, pid := range v.Parties {
			raw, _ := shares[tss.PartyID(pid)].MarshalBinary()
			v.KeygenShares = append(v.KeygenShares, hex.EncodeToString(raw))
		}
		signerCount := 2
		if v.N == 1 {
			signerCount = 1
		}
		signers := make([]tss.PartyID, signerCount)
		signerShares := make([]*KeyShare, signerCount)
		for j := range signers {
			signers[j] = tss.PartyID(v.Parties[j])
			signerShares[j] = shares[signers[j]]
		}
		presigns := secpPresign(t, shares, signers)
		for _, pid := range signers {
			raw, _ := presigns[pid].MarshalBinary()
			v.Presigns = append(v.Presigns, hex.EncodeToString(raw))
		}
		digest, err := hex.DecodeString(v.Digest)
		if err != nil {
			t.Fatal(err)
		}
		_, sig, err := SignDigest(digest, signerShares)
		if err != nil {
			t.Fatal(err)
		}
		v.Signature = &cggmpSigVector{R: hex.EncodeToString(sig.R), S: hex.EncodeToString(sig.S)}
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
