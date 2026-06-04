package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
)

type cggmp21TestVector struct {
	Description    string          `json:"description"`
	Threshold      int             `json:"threshold"`
	N              int             `json:"n"`
	Parties        []int           `json:"parties"`
	Seed           string          `json:"seed"`
	GroupPublicKey string          `json:"group_public_key"`
	KeygenShares   []string        `json:"keygen_shares"`
	Presigns       []string        `json:"presigns"`
	Digest         string          `json:"digest"`
	Signature      *cggmpSigVector `json:"signature"`
}

type cggmpSigVector struct {
	R string `json:"r"`
	S string `json:"s"`
}

func generateCGGMP21Vectors(t *testing.T) []cggmp21TestVector {
	t.Helper()

	run := func(threshold, n int, signerIDs []tss.PartyID) cggmp21TestVector {
		shares := secpKeygen(t, threshold, n)

		parties := make([]int, n)
		keygenShares := make([]string, n)
		pubKey := ""
		for i := range n {
			parties[i] = i + 1
			raw, err := shares[tss.PartyID(i+1)].MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			keygenShares[i] = hex.EncodeToString(raw)
			pubKey = hex.EncodeToString(shares[tss.PartyID(i+1)].PublicKey)
		}

		presignMap := secpPresign(t, shares, signerIDs)
		presigns := make([]string, len(signerIDs))
		for j, pid := range signerIDs {
			raw, err := presignMap[pid].MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			presigns[j] = hex.EncodeToString(raw)
		}

		digest := sha256.Sum256(fmt.Appendf(nil, "test message %d-of-%d", threshold, n))
		signerShares := make([]*KeyShare, len(signerIDs))
		for j, pid := range signerIDs {
			signerShares[j] = shares[pid]
		}
		_, sig, err := SignDigest(digest[:], signerShares)
		if err != nil {
			t.Fatal(err)
		}

		return cggmp21TestVector{
			Description:    fmt.Sprintf("CGGMP21 secp256k1 %d-of-%d keygen", threshold, n),
			Threshold:      threshold,
			N:              n,
			Parties:        parties,
			GroupPublicKey: pubKey,
			KeygenShares:   keygenShares,
			Presigns:       presigns,
			Digest:         hex.EncodeToString(digest[:]),
			Signature:      &cggmpSigVector{R: hex.EncodeToString(sig.R), S: hex.EncodeToString(sig.S)},
		}
	}

	return []cggmp21TestVector{
		run(1, 1, []tss.PartyID{1}),
		run(2, 3, []tss.PartyID{1, 2}),
	}
}

func TestGenerateCGGMP21Vectors(t *testing.T) {
	if os.Getenv("GENERATE_VECTORS") != "1" {
		t.Skip("set GENERATE_VECTORS=1 to regenerate cross-implementation vectors")
	}
	vectorPath := filepath.Join("testdata", "cggmp21_secp256k1_vectors.json")
	vectors := generateCGGMP21Vectors(t)
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors to %s", len(vectors), vectorPath)
}

func TestCGGMP21CrossImplementationVectors(t *testing.T) {
	vectorPath := filepath.Join("testdata", "cggmp21_secp256k1_vectors.json")
	data, err := os.ReadFile(vectorPath) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	var vectors []cggmp21TestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			for i, pid := range v.Parties {
				raw, err := hex.DecodeString(v.KeygenShares[i])
				if err != nil {
					t.Fatal(err)
				}
				share, err := UnmarshalKeyShare(raw)
				if err != nil {
					t.Fatalf("UnmarshalKeyShare for party %d: %v", pid, err)
				}
				if err := share.Validate(); err != nil {
					t.Fatalf("key share %d validation: %v", pid, err)
				}
				if hex.EncodeToString(share.PublicKey) != v.GroupPublicKey {
					t.Fatalf("party %d public key does not match group public key in vector", pid)
				}
				// Verify round-trip encoding is stable.
				reEncoded, err := share.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reEncoded, raw) {
					t.Fatalf("key share %d re-encoding changed — possible wire format regression", pid)
				}
			}

			for i, presignHex := range v.Presigns {
				raw, err := hex.DecodeString(presignHex)
				if err != nil {
					t.Fatal(err)
				}
				presign, err := UnmarshalPresign(raw)
				if err != nil {
					t.Fatalf("UnmarshalPresign %d: %v", i, err)
				}
				if err := presign.Validate(); err != nil {
					t.Fatalf("presign %d validation: %v", i, err)
				}
				reEncoded, err := presign.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reEncoded, raw) {
					t.Fatalf("presign %d re-encoding changed", i)
				}
			}

			// Verify that a fresh sign with these shares produces a valid signature.
			digest, err := hex.DecodeString(v.Digest)
			if err != nil {
				t.Fatal(err)
			}
			signerCount := 2
			if v.N == 1 {
				signerCount = 1
			}
			signerIDs := make([]tss.PartyID, signerCount)
			signerShares := make([]*KeyShare, signerCount)
			for j := range signerIDs {
				signerIDs[j] = tss.PartyID(v.Parties[j])
				raw, _ := hex.DecodeString(v.KeygenShares[j])
				signerShares[j], _ = UnmarshalKeyShare(raw)
			}
			pubKey, _ := hex.DecodeString(v.GroupPublicKey)
			_, sig, err := SignDigest(digest, signerShares)
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}
			if !VerifyDigest(signerShares[0].PublicKey, digest, sig) {
				t.Fatal("signature from deserialized shares did not verify")
			}

			// Verify the stored signature against the group public key.
			if v.Signature != nil {
				storedR, err := hex.DecodeString(v.Signature.R)
				if err != nil {
					t.Fatal(err)
				}
				storedS, err := hex.DecodeString(v.Signature.S)
				if err != nil {
					t.Fatal(err)
				}
				storedSig := &Signature{R: storedR, S: storedS}
				if !VerifyDigest(pubKey, digest, storedSig) {
					t.Fatal("stored signature does not verify against group public key")
				}
			}
		})
	}
}
