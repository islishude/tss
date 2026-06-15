package mta

import (
	"context"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/testutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func testSecurityParams() zkpai.SecurityParams {
	return zkpai.SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
}

// setupTestEnv creates fresh Paillier keys and Ring-Pedersen parameters with
// reduced security parameters for Tier 1 tests.
func setupTestEnv(tb testing.TB) (skA, skB *pai.PrivateKey, rpA, rpB *zkpai.RingPedersenParams) {
	tb.Helper()
	var err error
	skA, err = pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	skB, err = pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	rpA, _, err = zkpai.GenerateRingPedersenParams(nil, skA)
	if err != nil {
		tb.Fatal(err)
	}
	rpB, _, err = zkpai.GenerateRingPedersenParams(nil, skB)
	if err != nil {
		tb.Fatal(err)
	}
	return skA, skB, rpA, rpB
}

func seedMessages(tb testing.TB) (*StartMessage, *ResponseMessage) {
	tb.Helper()
	skA, skB, rpA, rpB := setupTestEnv(tb)
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		tb.Fatal(err)
	}
	start, err := Start(nil, a, &skA.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	params := testSecurityParams()
	startProof, err := ProveStartForVerifier(params, nil, []byte("start"), start, &skA.PublicKey, *rpB)
	if err != nil {
		tb.Fatal(err)
	}
	response, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
	if err != nil {
		tb.Fatal(err)
	}
	return &start.Message, response
}

// Tier 0: helper validation tests (no crypto keygen).

func TestValidatePositiveIntegerBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "empty", input: nil, wantErr: "empty integer"},
		{name: "zero len", input: []byte{}, wantErr: "empty integer"},
		{name: "leading zero", input: []byte{0x00, 0x01}, wantErr: "non-minimal integer encoding"},
		{name: "zero value", input: []byte{0x00}, wantErr: "non-minimal integer encoding"},
		{name: "all zeros", input: []byte{0x00, 0x00, 0x00}, wantErr: "non-minimal integer encoding"},
		{name: "valid small", input: []byte{0x01}, wantErr: ""},
		{name: "valid medium", input: []byte{0x42}, wantErr: ""},
		{name: "valid large", input: []byte{0xFF, 0xFF, 0xFF}, wantErr: ""},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validatePositiveIntegerBytes(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("got error %q, want %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

func TestScalarFixedBytes(t *testing.T) {
	t.Parallel()

	t.Run("short scalar padded to 32 bytes", func(t *testing.T) {
		t.Parallel()

		x := big.NewInt(13)
		b := scalarFixedBytes(x)
		if len(b) != 32 {
			t.Fatalf("got %d bytes, want 32", len(b))
		}
		if new(big.Int).SetBytes(b).Cmp(x) != 0 {
			t.Fatal("round-trip mismatch")
		}
	})
	t.Run("exact 32 byte scalar", func(t *testing.T) {
		t.Parallel()

		x := new(big.Int)
		for i := range 32 {
			x.Lsh(x, 8)
			x.Or(x, big.NewInt(int64(i+1)))
		}
		b := scalarFixedBytes(x)
		if len(b) != 32 {
			t.Fatalf("got %d bytes, want 32", len(b))
		}
		// Truncation expected — only lower 32 bytes preserved.
		got := new(big.Int).SetBytes(b)
		want := new(big.Int).Mod(x, new(big.Int).Lsh(big.NewInt(1), 256))
		if got.Cmp(want) != 0 {
			t.Fatalf("truncation mismatch")
		}
	})
}

func TestRandomScalar(t *testing.T) {
	t.Parallel()

	x, err := randomScalar(testutil.DeterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	if x.Sign() <= 0 {
		t.Fatal("random scalar must be positive")
	}
	if x.Cmp(secp.Order()) >= 0 {
		t.Fatal("random scalar out of range")
	}

	xAgain, err := randomScalar(testutil.DeterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	if x.Cmp(xAgain) != 0 {
		t.Fatal("randomScalar did not consume deterministic reader reproducibly")
	}
}

func TestMessageVersion(t *testing.T) {
	t.Parallel()

	if messageVersion != 1 {
		t.Fatal("messageVersion changed; wire format may be incompatible")
	}
}
