package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/testvectors"
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
	parties := testutil.MustPartySet(n)
	session, err := tss.NewSessionID(rng)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[tss.PartyID]*KeygenSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		cfg := tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session, Rand: rng}
		kg, out, err := startFROSTKeygen(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	deliverFROSTKeygenMessages(t, parties, sessions, messages)
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
	t.Parallel()
	data := testvectors.Read(t, "protocol/frost-ed25519/frost_ed25519_vectors.json")
	var vectors []frostTestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			// Regenerate key shares from the same seed and verify consistency.
			shares := frostVectorKeygen(t, v.Seed, v.Threshold, v.N)

			// Verify group public key matches.
			if hex.EncodeToString(shares[0].state.PublicKey.Bytes()) != v.GroupPublicKey {
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
				restored, err := tss.DecodeBinary[KeyShare](raw)
				if err != nil {
					t.Fatalf("UnmarshalKeyShare: %v", err)
				}
				if err := restored.Validate(); err != nil {
					t.Fatalf("restored key share validation: %v", err)
				}
				if !restored.state.PublicKey.Equal(share.state.PublicKey) {
					t.Fatal("round-tripped public key mismatch")
				}
			}

			// Verify a fresh in-memory sign produces a valid Ed25519 signature.
			msg, err := hex.DecodeString(v.Message)
			if err != nil {
				t.Fatal(err)
			}
			signerCount := len(v.Signers)
			signerShares := make([]*KeyShare, signerCount)
			for j, pid := range v.Signers {
				signerShares[j] = shares[pid-1]
			}
			limits := testLimits()
			pub, sig, err := SignWithOptions(msg, signerShares, SignOptions{Context: testFROSTSigningContext(), Limits: &limits})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ed25519.Verify(pub, msg, sig) {
				t.Fatal("FROST signature failed ed25519 verification")
			}
			if v.Signature != "" {
				storedSig, err := hex.DecodeString(v.Signature)
				if err != nil {
					t.Fatal(err)
				}
				if !ed25519.Verify(shares[0].state.PublicKey.Bytes(), msg, storedSig) {
					t.Fatal("stored signature does not verify against group public key")
				}
			}
		})
	}
}
