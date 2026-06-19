//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
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
	data := testvectors.Read(t, "protocol/cggmp21-secp256k1/cggmp21_secp256k1_vectors.json")
	var vectors []cggmp21TestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			t.Parallel()

			for i, pid := range v.Parties {
				raw, err := hex.DecodeString(v.KeygenShares[i])
				if err != nil {
					t.Fatal(err)
				}
				share, err := UnmarshalKeyShareWithLimits(raw, testLimits())
				if err != nil {
					t.Fatalf("UnmarshalKeyShare for party %d: %v", pid, err)
				}
				if err := share.ValidateWithLimits(testLimits()); err != nil {
					t.Fatalf("key share %d validation: %v", pid, err)
				}
				if hex.EncodeToString(share.PublicKeyBytes()) != v.GroupPublicKey {
					t.Fatalf("party %d public key does not match group public key in vector", pid)
				}
				// Verify round-trip encoding is stable.
				reEncoded, err := share.MarshalBinaryWithLimits(testLimits())
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
				presign, err := UnmarshalPresignWithLimits(raw, testLimits())
				if err != nil {
					t.Fatalf("UnmarshalPresign %d: %v", i, err)
				}
				if err := presign.ValidateWithLimits(testLimits()); err != nil {
					t.Fatalf("presign %d validation: %v", i, err)
				}
				reEncoded, err := presign.MarshalBinaryWithLimits(testLimits())
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
			signerCount := v.Threshold
			signerIDs := make(tss.PartySet, signerCount)
			signerShares := make([]*KeyShare, signerCount)
			for j := range signerIDs {
				signerIDs[j] = tss.PartyID(v.Parties[j])
				raw, _ := hex.DecodeString(v.KeygenShares[j])
				signerShares[j], _ = UnmarshalKeyShareWithLimits(raw, testLimits())
			}
			pubKey, _ := hex.DecodeString(v.GroupPublicKey)
			_, sig, err := SignDigest(digest, signerShares)
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}
			if !VerifyDigest(signerShares[0].PublicKeyBytes(), digest, sig) {
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
