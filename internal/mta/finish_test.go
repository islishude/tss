//go:build tier1

package mta

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// Tier 1: Finish error paths (needs crypto keygen).

func TestFinishErrors(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, rpB := setupTestEnv(t)
	params := testSecurityParams()

	a := big.NewInt(13)
	b := big.NewInt(37)
	start, err := Start(nil, a, &skA.PublicKey)
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
	response, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil skA", func(t *testing.T) {
		_, err := Finish(params, []byte("response"), start.Message, *response, bCommit, nil, &skB.PublicKey, *rpA)
		if err == nil {
			t.Fatal("expected error for nil Paillier private key")
		}
	})

	t.Run("invalid start message", func(t *testing.T) {
		badStart := StartMessage{Ciphertext: nil}
		_, err := Finish(params, []byte("response"), badStart, *response, bCommit, skA, &skB.PublicKey, *rpA)
		if err == nil {
			t.Fatal("expected error for invalid start message")
		}
	})

	t.Run("invalid b commitment", func(t *testing.T) {
		_, err := Finish(params, []byte("response"), start.Message, *response, []byte{0x00, 0x01}, skA, &skB.PublicKey, *rpA)
		if err == nil {
			t.Fatal("expected error for invalid b commitment")
		}
	})

	t.Run("empty b commitment", func(t *testing.T) {
		_, err := Finish(params, []byte("response"), start.Message, *response, nil, skA, &skB.PublicKey, *rpA)
		if err == nil {
			t.Fatal("expected error for empty b commitment")
		}
	})

	t.Run("invalid response proof", func(t *testing.T) {
		badResponse := *response
		badResponse.Proof = []byte{0xFF, 0xFE, 0xFD}
		_, err := Finish(params, []byte("response"), start.Message, badResponse, bCommit, skA, &skB.PublicKey, *rpA)
		if err == nil {
			t.Fatal("expected error for invalid response proof")
		}
	})

	t.Run("wrong response domain", func(t *testing.T) {
		_, err := Finish(params, []byte("wrong-domain"), start.Message, *response, bCommit, skA, &skB.PublicKey, *rpA)
		if err == nil {
			t.Fatal("expected error for wrong response domain")
		}
	})
}

func TestFinishMultipleValues(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, rpB := setupTestEnv(t)
	params := testSecurityParams()
	startDomain := []byte("start")
	responseDomain := []byte("response")

	pairs := []struct{ a, b int64 }{
		{1, 1},
		{2, 3},
		{7, 11},
		{42, 99},
		{1 << 20, 1 << 20},
	}
	for _, p := range pairs {
		a := big.NewInt(p.a)
		b := big.NewInt(p.b)
		bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
		if err != nil {
			t.Fatal(err)
		}
		start, err := Start(nil, a, &skA.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		startProof, err := ProveStartForVerifier(params, nil, startDomain, start, &skA.PublicKey, *rpB)
		if err != nil {
			t.Fatal(err)
		}
		response, betaShare, err := Respond(params, nil, startDomain, responseDomain, start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err != nil {
			t.Fatal(err)
		}
		alphaShare, err := Finish(params, responseDomain, start.Message, *response, bCommit, skA, &skB.PublicKey, *rpA)
		if err != nil {
			t.Fatal(err)
		}
		got := new(big.Int).Add(alphaShare, betaShare)
		got.Mod(got, secp.Order())
		want := new(big.Int).Mul(a, b)
		want.Mod(want, secp.Order())
		if got.Cmp(want) != 0 {
			t.Fatalf("a=%d b=%d: alpha+beta = %s mod q, want %s", p.a, p.b, got, want)
		}
	}
}
