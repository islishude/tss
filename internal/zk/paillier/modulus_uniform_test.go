package paillier

import (
	"math/big"
	"testing"
)

func TestReduceUniformModulusCandidateExactPreimages(t *testing.T) {
	t.Parallel()

	// For N=15 and one-byte candidates, M=256 and
	// floor(M/N)*N=255. Every residue has exactly 17 preimages before the
	// non-unit filter, so every member of Z*_15 must remain exactly uniform.
	n := big.NewInt(15)
	limit, err := modulusRejectionLimit(n, 1)
	if err != nil {
		t.Fatal(err)
	}
	if limit.Cmp(big.NewInt(255)) != 0 {
		t.Fatalf("rejection limit = %v, want 255", limit)
	}

	counts := make(map[int64]int)
	for candidate := range 256 {
		value, ok := reduceUniformModulusCandidate([]byte{byte(candidate)}, n, limit)
		if !ok {
			continue
		}
		counts[value.Int64()]++
	}
	wantUnits := []int64{1, 2, 4, 7, 8, 11, 13, 14}
	if len(counts) != len(wantUnits) {
		t.Fatalf("accepted unit count = %d, want %d", len(counts), len(wantUnits))
	}
	for _, unit := range wantUnits {
		if counts[unit] != 17 {
			t.Errorf("unit %d has %d preimages, want 17", unit, counts[unit])
		}
	}
	if _, ok := reduceUniformModulusCandidate([]byte{255}, n, limit); ok {
		t.Fatal("candidate at rejection cutoff was accepted")
	}
}

func TestDeriveModulusYReturnsDeterministicUnit(t *testing.T) {
	t.Parallel()

	n := big.NewInt(15)
	root := make([]byte, 32)
	a, err := deriveModulusY(n, root, 7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveModulusY(n, root, 7)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cmp(b) != 0 {
		t.Fatal("same modulus transcript and round produced different challenges")
	}
	if a.Sign() <= 0 || a.Cmp(n) >= 0 || new(big.Int).GCD(nil, nil, a, n).Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("derived challenge %v is not in Z*_N", a)
	}
}

func TestModulusRejectionHelpersRejectInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := modulusRejectionLimit(nil, 1); err == nil {
		t.Fatal("nil modulus accepted")
	}
	if _, err := modulusRejectionLimit(big.NewInt(257), 1); err == nil {
		t.Fatal("modulus larger than candidate space accepted")
	}
	if _, ok := reduceUniformModulusCandidate(nil, big.NewInt(15), big.NewInt(255)); ok {
		t.Fatal("empty candidate accepted")
	}
	if _, err := deriveModulusY(big.NewInt(15), make([]byte, 32), -1); err == nil {
		t.Fatal("negative modulus proof round accepted")
	}
}
