package challenge

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestDeriveCanonicalNonZeroSecp256k1Boundaries(t *testing.T) {
	t.Parallel()

	order := secp.Order()
	tests := []struct {
		name      string
		candidate *big.Int
		accept    bool
	}{
		{name: "zero", candidate: new(big.Int), accept: false},
		{name: "q minus one", candidate: new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1)), accept: true},
		{name: "q", candidate: new(big.Int).Set(order), accept: false},
		{name: "q plus one", candidate: new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1)), accept: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			candidate := tc.candidate.FillBytes(make([]byte, sha256.Size))
			got, ok := canonicalNonZeroSecp256k1Candidate(candidate)
			if tc.accept {
				if !ok {
					t.Fatal("canonical boundary candidate was rejected")
				}
				if !bytes.Equal(got.Bytes(), candidate) {
					t.Fatal("accepted challenge changed its canonical representative")
				}
				return
			}
			if ok {
				t.Fatal("non-canonical boundary candidate was accepted")
			}
		})
	}
}

func TestDeriveCanonicalNonZeroSecp256k1RetriesDeterministically(t *testing.T) {
	t.Parallel()

	root := make([]byte, sha256.Size)
	a, err := DeriveCanonicalNonZeroSecp256k1("challenge-retry-a", root, 256)
	if err != nil {
		t.Fatal(err)
	}
	aAgain, err := DeriveCanonicalNonZeroSecp256k1("challenge-retry-a", root, 256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveCanonicalNonZeroSecp256k1("challenge-retry-b", root, 256)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(aAgain) {
		t.Fatal("same root and domain produced different challenges")
	}
	if a.Equal(b) {
		t.Fatal("retry derivation did not bind its domain")
	}
}

func TestDeriveNonZeroBitsRetriesMaskedZero(t *testing.T) {
	t.Parallel()

	root := make([]byte, sha256.Size)
	value, err := DeriveNonZeroBits("challenge-reduced-test", root, 1, 256)
	if err != nil {
		t.Fatal(err)
	}
	if value.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("one-bit non-zero challenge = %v, want 1", value)
	}
}

func TestDeriveChallengeRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	root := make([]byte, sha256.Size)
	for _, tc := range []struct {
		name    string
		domain  string
		root    []byte
		attempt uint32
	}{
		{name: "empty domain", root: root, attempt: 1},
		{name: "short root", domain: "test", root: root[:sha256.Size-1], attempt: 1},
		{name: "zero attempts", domain: "test", root: root},
		{name: "too many attempts", domain: "test", root: root, attempt: 257},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DeriveCanonicalNonZeroSecp256k1(tc.domain, tc.root, tc.attempt); err == nil {
				t.Fatal("invalid challenge configuration accepted")
			}
		})
	}
	if _, err := DeriveNonZeroBits("test", root, 0, 1); err == nil {
		t.Fatal("zero reduced challenge width accepted")
	}
	if _, err := DeriveNonZeroBits("test", root, 257, 1); err == nil {
		t.Fatal("oversized reduced challenge width accepted")
	}
}
