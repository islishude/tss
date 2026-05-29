package secp256k1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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
