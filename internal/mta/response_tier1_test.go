//go:build tier1

package mta

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

// Tier 0: ResponseMessage validation and wire error paths (no crypto keygen).

func TestRespondErrors(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, rpB := setupTestEnv(t)
	params := testSecurityParams()

	a := big.NewInt(13)
	b := big.NewInt(37)
	bSecret := testSecretScalar(t, b)
	start, err := Start(nil, testSecretScalar(t, a), &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(params, nil, []byte("start"), start, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil b", func(t *testing.T) {
		_, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, nil, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for nil b")
		}
	})
	t.Run("zero b", func(t *testing.T) {
		_, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, testSecretScalar(t, big.NewInt(0)), bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for zero b")
		}
	})
	t.Run("wrong width b", func(t *testing.T) {
		wrongWidth, scalarErr := secret.NewScalar([]byte{5}, secp.ScalarSize-1)
		if scalarErr != nil {
			t.Fatal(scalarErr)
		}
		defer wrongWidth.Destroy()
		_, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, wrongWidth, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for wrong-width b")
		}
	})
	t.Run("b at order", func(t *testing.T) {
		_, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, testSecretScalar(t, secp.Order()), bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for b at order")
		}
	})
	t.Run("invalid start message", func(t *testing.T) {
		badStart := StartMessage{Ciphertext: nil}
		_, _, err := Respond(params, nil, []byte("start"), []byte("response"), badStart, startProof, bSecret, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for invalid start message")
		}
	})
	t.Run("wrong start proof domain", func(t *testing.T) {
		_, _, err := Respond(params, nil, []byte("wrong-domain"), []byte("response"), start.Message, startProof, bSecret, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for wrong start proof domain")
		}
	})
}

func TestRespondBoundaryValues(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, rpB := setupTestEnv(t)
	params := testSecurityParams()
	startProofDomain := []byte("start")
	responseDomain := []byte("response")

	a := big.NewInt(13)
	start, err := Start(nil, testSecretScalar(t, a), &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(params, nil, startProofDomain, start, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}

	orderMinus1 := new(big.Int).Sub(secp.Order(), big.NewInt(1))
	bValues := []struct {
		name string
		b    *big.Int
	}{
		{name: "b=1", b: big.NewInt(1)},
		{name: "b=order-1", b: orderMinus1},
	}
	for _, bv := range bValues {
		t.Run(bv.name, func(t *testing.T) {
			bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(bv.b)))
			if err != nil {
				t.Fatal(err)
			}
			response, betaShare, err := Respond(params, nil, startProofDomain, responseDomain, start.Message, startProof, testSecretScalar(t, bv.b), bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if response == nil {
				t.Fatal("nil response")
			}
			if betaShare == nil {
				t.Fatal("nil beta share")
			}
		})
	}
}
