//go:build tier1

package mta

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

// Tier 0: StartMessage validation and wire error paths (no crypto keygen).

func TestStartErrors(t *testing.T) {
	t.Parallel()
	skA, _, _, _ := setupTestEnv(t)

	tests := []struct {
		name string
		a    *secret.Scalar
	}{
		{name: "nil a", a: nil},
		{name: "zero a", a: testSecretScalar(t, big.NewInt(0))},
		{name: "wrong width", a: func() *secret.Scalar {
			out, err := secret.NewScalar([]byte{1}, secp.ScalarSize-1)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(out.Destroy)
			return out
		}()},
		{name: "a at order", a: testSecretScalar(t, secp.Order())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Start(nil, tt.a, &skA.PublicKey)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestStartBoundaryValues(t *testing.T) {
	t.Parallel()
	skA, _, _, _ := setupTestEnv(t)

	orderMinus1 := new(big.Int).Sub(secp.Order(), big.NewInt(1))
	tests := []struct {
		name string
		a    *secret.Scalar
	}{
		{name: "a=1", a: testSecretScalar(t, big.NewInt(1))},
		{name: "a=order-1", a: testSecretScalar(t, orderMinus1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opening, err := Start(nil, tt.a, &skA.PublicKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opening == nil {
				t.Fatal("nil opening")
			}
		})
	}
}

func TestProveStartForVerifierErrors(t *testing.T) {
	t.Parallel()
	skA, _, _, rpB := setupTestEnv(t)
	params := testSecurityParams()

	t.Run("nil opening", func(t *testing.T) {
		_, err := ProveStartForVerifier(params, nil, nil, nil, &skA.PublicKey, *rpB)
		if err == nil {
			t.Fatal("expected error for nil opening")
		}
		if err.Error() != "nil MtA start opening" {
			t.Fatalf("got %q, want %q", err.Error(), "nil MtA start opening")
		}
	})

	t.Run("opening with invalid ciphertext", func(t *testing.T) {
		opening := &StartOpening{
			Message: StartMessage{Ciphertext: nil},
			k:       testSecretScalar(t, big.NewInt(13)),
			rho:     testSecretScalar(t, big.NewInt(37)),
		}
		_, err := ProveStartForVerifier(params, nil, nil, opening, &skA.PublicKey, *rpB)
		if err == nil {
			t.Fatal("expected error for opening with invalid message")
		}
	})
}

func TestVerifyStartErrors(t *testing.T) {
	t.Parallel()
	skA, _, _, rpB := setupTestEnv(t)
	params := testSecurityParams()

	opening, err := Start(nil, testSecretScalar(t, big.NewInt(42)), &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveStartForVerifier(params, nil, []byte("domain"), opening, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("empty proof", func(t *testing.T) {
		err := VerifyStart(params, []byte("domain"), opening.Message, &skA.PublicKey, *rpB, nil)
		if err == nil {
			t.Fatal("expected error for empty proof")
		}
	})

	t.Run("truncated proof", func(t *testing.T) {
		truncated := proof.Clone()
		truncated.TranscriptHash = truncated.TranscriptHash[:4]
		err := VerifyStart(params, []byte("domain"), opening.Message, &skA.PublicKey, *rpB, truncated)
		if err == nil {
			t.Fatal("expected error for truncated proof")
		}
	})

	t.Run("garbled proof", func(t *testing.T) {
		garbled := proof.Clone()
		err := VerifyStart(params, []byte("domain"), opening.Message, &skA.PublicKey, *rpB, garbled)
		if err == nil {
			t.Fatal("expected error for garbled proof")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		err := VerifyStart(params, []byte("other-domain"), opening.Message, &skA.PublicKey, *rpB, proof)
		if err == nil {
			t.Fatal("expected error for wrong domain")
		}
	})
}
