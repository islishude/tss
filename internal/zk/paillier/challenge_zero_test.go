package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestProductionChallengeIsCanonicalNonZeroScalar(t *testing.T) {
	t.Parallel()

	transcript := NewTranscript("challenge-zero-test")
	transcript.AppendBytes("test", []byte("data"))
	e, err := transcript.ChallengeSigned(256)
	if err != nil {
		t.Fatal(err)
	}
	encoded := e.FillBytes(make([]byte, secp.ScalarSize))
	challenge, err := secp.ScalarFromBytes(encoded)
	if err != nil {
		t.Fatalf("production challenge is not a canonical non-zero scalar: %v", err)
	}
	if challenge.IsZero() {
		t.Fatal("production challenge is an effective zero scalar")
	}
}

// TestChallengeBitsMatchClaim verifies that ChallengeSigned with bits=N
// returns values in [1, 2^N). A challenge outside this range would indicate
// a bug in the bit-masking logic.
func TestChallengeBitsMatchClaim(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint32{64, 128} {
		bound := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		for i := range 100 {
			transcript := NewTranscript("challenge-range-test")
			transcript.AppendBytes("index", []byte{byte(i), byte(i >> 8)})
			e, err := transcript.ChallengeSigned(bits)
			if err != nil {
				t.Fatalf("bits=%d: ChallengeSigned failed at iteration %d: %v", bits, i, err)
			}
			if e.Sign() == 0 {
				t.Fatalf("bits=%d: zero challenge at iteration %d", bits, i)
			}
			if e.Cmp(bound) >= 0 {
				t.Fatalf("bits=%d: challenge %s >= 2^%d at iteration %d", bits, e, bits, i)
			}
		}
	}

	// Rejection sampling makes the only valid one-bit challenge deterministically
	// equal to one rather than surfacing masked-zero failures to proof callers.
	for i := range 200 {
		transcript := NewTranscript("challenge-1bit-test")
		transcript.AppendBytes("index", []byte{byte(i), byte(i >> 8)})
		e, err := transcript.ChallengeSigned(1)
		if err != nil {
			t.Fatal(err)
		}
		if e.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("1-bit challenge = %s, want 1", e)
		}
	}
}
