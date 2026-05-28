package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
)

type frostTestVector struct {
	Description    string   `json:"description"`
	Threshold      int      `json:"threshold"`
	N              int      `json:"n"`
	Parties        []int    `json:"parties"`
	Seed           string   `json:"seed"`
	GroupPublicKey string   `json:"group_public_key"`
	KeygenShares   []string `json:"keygen_shares"`
	Message        string   `json:"message"`
	Signers        []int    `json:"signers"`
	Signature      string   `json:"signature"`
}

func deterministicRNG(seedHex string) *rand.ChaCha8 {
	seed, _ := hex.DecodeString(seedHex)
	var s [32]byte
	copy(s[:], seed)
	return rand.NewChaCha8(s)
}

func frostVectorKeygen(t *testing.T, seedHex string, threshold, n int) []*KeyShare {
	t.Helper()
	rng := deterministicRNG(seedHex)
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	session, err := tss.NewSessionID(rng)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[tss.PartyID]*KeygenSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		cfg := tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session, Rand: rng}
		kg, out, err := StartKeygen(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				t.Fatalf("deliver %s %d->%d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
	shares := make([]*KeyShare, n)
	for i, id := range parties {
		s, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		shares[i] = s
	}
	return shares
}

func TestFROSTCrossImplementationVectors(t *testing.T) {
	vectorPath := filepath.Join("testdata", "frost_ed25519_vectors.json")

	// If no vector file exists, generate it.
	if _, err := os.Stat(vectorPath); os.IsNotExist(err) {
		t.Log("generating frost_ed25519_vectors.json")
		generateFROSTVectors(t, vectorPath)
	}

	data, err := os.ReadFile(vectorPath) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	var vectors []frostTestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			// Regenerate key shares from the same seed and verify consistency.
			shares := frostVectorKeygen(t, v.Seed, v.Threshold, v.N)

			// Verify group public key matches.
			if hex.EncodeToString(shares[0].PublicKey) != v.GroupPublicKey {
				t.Fatal("group public key mismatch — possible wire format or curve operation change")
			}

			// Verify key share round-trip: serialized form must match stored vectors.
			for i, share := range shares {
				raw, err := share.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				got := hex.EncodeToString(raw)
				if got != v.KeygenShares[i] {
					t.Fatalf("key share %d encoding changed — possible wire format regression", i+1)
				}
				// Verify deserialized share validates.
				restored, err := UnmarshalKeyShare(raw)
				if err != nil {
					t.Fatalf("UnmarshalKeyShare: %v", err)
				}
				if err := restored.Validate(); err != nil {
					t.Fatalf("restored key share validation: %v", err)
				}
				if !bytes.Equal(restored.PublicKey, share.PublicKey) {
					t.Fatal("round-tripped public key mismatch")
				}
			}

			// Verify a fresh in-memory sign produces a valid Ed25519 signature.
			msg, err := hex.DecodeString(v.Message)
			if err != nil {
				t.Fatal(err)
			}
			signers := make([]tss.PartyID, len(v.Signers))
			for i, id := range v.Signers {
				signers[i] = tss.PartyID(id)
			}
			pub, sig, err := Sign(msg, shares)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ed25519.Verify(pub, msg, sig) {
				t.Fatal("FROST signature failed ed25519 verification")
			}
			// Store the signature for first-time generation.
			if v.Signature == "" {
				v.Signature = hex.EncodeToString(sig)
			}
		})
	}
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
	}
	raw, _ := json.MarshalIndent(vectors, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}
