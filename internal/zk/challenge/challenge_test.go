package challenge

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
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

func TestDeriveCanonicalNonZeroEd25519Boundaries(t *testing.T) {
	t.Parallel()

	order := edcurve.Order()
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
			slices.Reverse(candidate)
			got, ok := canonicalNonZeroEd25519Candidate(candidate)
			if tc.accept {
				if !ok {
					t.Fatal("canonical boundary candidate was rejected")
				}
				if !bytes.Equal(got.Bytes(), candidate) {
					t.Fatal("accepted challenge changed its canonical representative")
				}
				got.Set(fed.NewScalar())
				return
			}
			if ok {
				got.Set(fed.NewScalar())
				t.Fatal("non-canonical boundary candidate was accepted")
			}
		})
	}
}

func TestDeriveCanonicalNonZeroEd25519RetriesDeterministically(t *testing.T) {
	t.Parallel()

	root := make([]byte, sha256.Size)
	a, err := DeriveCanonicalNonZeroEd25519("ed25519-challenge-retry-a", root, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Set(fed.NewScalar())
	aAgain, err := DeriveCanonicalNonZeroEd25519("ed25519-challenge-retry-a", root, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer aAgain.Set(fed.NewScalar())
	b, err := DeriveCanonicalNonZeroEd25519("ed25519-challenge-retry-b", root, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Set(fed.NewScalar())
	if a.Equal(aAgain) != 1 {
		t.Fatal("same root and domain produced different challenges")
	}
	if a.Equal(b) == 1 {
		t.Fatal("retry derivation did not bind its domain")
	}
	if a.Equal(fed.NewScalar()) == 1 {
		t.Fatal("derived challenge was zero")
	}
	if _, err := fed.NewScalar().SetCanonicalBytes(a.Bytes()); err != nil {
		t.Fatalf("derived challenge was not canonical: %v", err)
	}
}

func TestDeriveCanonicalNonZeroEd25519RetriesRejectedCandidate(t *testing.T) {
	t.Parallel()

	root := make([]byte, sha256.Size)
	var domain string
	var expected *fed.Scalar
	for i := range 1024 {
		candidateDomain := fmt.Sprintf("ed25519-rejection-test-%d", i)
		first := challengeCandidate(candidateDomain, root, 0)
		first[len(first)-1] &= 0x1f
		firstScalar, firstAccepted := canonicalNonZeroEd25519Candidate(first)
		clear(first)
		if firstAccepted {
			firstScalar.Set(fed.NewScalar())
			continue
		}

		second := challengeCandidate(candidateDomain, root, 1)
		second[len(second)-1] &= 0x1f
		var secondAccepted bool
		expected, secondAccepted = canonicalNonZeroEd25519Candidate(second)
		clear(second)
		if secondAccepted {
			domain = candidateDomain
			break
		}
	}
	if expected == nil {
		t.Fatal("failed to find deterministic reject-then-accept challenge candidates")
	}
	defer expected.Set(fed.NewScalar())

	if _, err := DeriveCanonicalNonZeroEd25519(domain, root, 1); !errors.Is(err, ErrRejectionLimit) {
		t.Fatalf("one-candidate derivation returned %v, want rejection limit", err)
	}
	got, err := DeriveCanonicalNonZeroEd25519(domain, root, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Set(fed.NewScalar())
	if got.Equal(expected) != 1 {
		t.Fatal("derivation did not return the first accepted canonical candidate")
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
			if _, err := DeriveCanonicalNonZeroEd25519(tc.domain, tc.root, tc.attempt); err == nil {
				t.Fatal("invalid Ed25519 challenge configuration accepted")
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
