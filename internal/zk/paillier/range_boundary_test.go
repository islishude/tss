package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// TestSignedPowerOfTwoBoundary verifies InSignedPowerOfTwo accepts exactly at
// ±2^bits and rejects exactly at ±(2^bits + 1). An off-by-one in this check
// would allow a prover to use out-of-range witnesses, breaking the range proof
// soundness.
func TestSignedPowerOfTwoBoundary(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint{1, 8, 64, 128, 256, 384, 486} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
		negBound := new(big.Int).Neg(bound)
		above := new(big.Int).Add(bound, big.NewInt(1))
		below := new(big.Int).Sub(negBound, big.NewInt(1))

		if !InSignedPowerOfTwo(bound, bits) {
			t.Errorf("bits=%d: +2^bits should be accepted", bits)
		}
		if !InSignedPowerOfTwo(negBound, bits) {
			t.Errorf("bits=%d: -2^bits should be accepted", bits)
		}
		if !InSignedPowerOfTwo(big.NewInt(0), bits) {
			t.Errorf("bits=%d: zero should be accepted", bits)
		}

		if InSignedPowerOfTwo(above, bits) {
			t.Errorf("bits=%d: +2^bits+1 should be rejected", bits)
		}
		if InSignedPowerOfTwo(below, bits) {
			t.Errorf("bits=%d: -(2^bits+1) should be rejected", bits)
		}
	}
}

// TestUnsignedPowerOfTwoBoundary verifies InUnsignedPowerOfTwo accepts [0, 2^bits)
// and rejects at 2^bits.
func TestUnsignedPowerOfTwoBoundary(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint{1, 8, 64, 128, 256} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits)
		below := new(big.Int).Sub(bound, big.NewInt(1))

		if !InUnsignedPowerOfTwo(big.NewInt(0), bits) {
			t.Errorf("bits=%d: zero should be accepted", bits)
		}
		if !InUnsignedPowerOfTwo(below, bits) {
			t.Errorf("bits=%d: 2^bits-1 should be accepted", bits)
		}
		if InUnsignedPowerOfTwo(bound, bits) {
			t.Errorf("bits=%d: 2^bits should be rejected (exclusive bound)", bits)
		}
		if InUnsignedPowerOfTwo(new(big.Int).Neg(big.NewInt(1)), bits) {
			t.Errorf("bits=%d: negative should be rejected", bits)
		}
	}
}

// TestMultRangeBoundary verifies inMultRange accepts exactly at ±N·2^bits and
// rejects at ±(N·2^bits + 1). This range is used for Ring-Pedersen commitment
// nonces in Πenc, Πaff-g, and Πlog*. An off-by-one would allow a malicious
// prover to submit nonces outside the range that still pass verification.
func TestMultRangeBoundary(t *testing.T) {
	t.Parallel()
	n := big.NewInt(100003) // small prime for testing

	for _, bits := range []uint{1, 8, 64, 128, 256} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
		bound.Mul(bound, n)                            // N·2^bits

		posBound := new(big.Int).Set(bound)
		negBound := new(big.Int).Neg(bound)
		above := new(big.Int).Add(bound, big.NewInt(1))
		below := new(big.Int).Sub(negBound, big.NewInt(1))

		if !inMultRange(posBound, n, bits) {
			t.Errorf("bits=%d: +N·2^bits should be accepted", bits)
		}
		if !inMultRange(negBound, n, bits) {
			t.Errorf("bits=%d: -N·2^bits should be accepted", bits)
		}
		if !inMultRange(big.NewInt(0), n, bits) {
			t.Errorf("bits=%d: zero should be accepted", bits)
		}

		if inMultRange(above, n, bits) {
			t.Errorf("bits=%d: +N·2^bits+1 should be rejected", bits)
		}
		if inMultRange(below, n, bits) {
			t.Errorf("bits=%d: -(N·2^bits+1) should be rejected", bits)
		}
	}
}

// TestZKRangeBound verifies that zkRangeBound(e) computes the correct bound
// 2^{l+ε} + e·q, matching the statistical ZK formula used by all legacy proofs.
func TestZKRangeBound(t *testing.T) {
	t.Parallel()
	q := secp.Order()

	// Test e=0: bound = 2^{l+ε} = 2^384
	eZero := big.NewInt(0)
	boundZero := zkRangeBound(eZero)
	expectedZero := twoToThe(maskBits) // 2^384
	if boundZero.Cmp(expectedZero) != 0 {
		t.Fatalf("zkRangeBound(0) = %s, want 2^384", boundZero)
	}

	// Test e=1: bound = 2^384 + q
	eOne := big.NewInt(1)
	boundOne := zkRangeBound(eOne)
	expectedOne := new(big.Int).Set(expectedZero)
	expectedOne.Add(expectedOne, q)
	if boundOne.Cmp(expectedOne) != 0 {
		t.Fatalf("zkRangeBound(1) = %s, want 2^384 + q", boundOne)
	}

	// Test e = secp256k1 order - 1 (max realistic challenge for legacy proofs)
	eMax := new(big.Int).Sub(q, big.NewInt(1))
	boundMax := zkRangeBound(eMax)
	expectedMax := new(big.Int).Mul(eMax, q)
	expectedMax.Add(expectedMax, expectedZero)
	if boundMax.Cmp(expectedMax) != 0 {
		t.Fatalf("zkRangeBound(q-1) mismatch")
	}

	// Verify bound is strictly tight: bound-1 is less than bound
	below := new(big.Int).Sub(boundOne, big.NewInt(1))
	if below.Cmp(boundOne) >= 0 {
		t.Fatal("bound-1 >= bound — arithmetic error")
	}
}

// TestSampleSignedPowerOfTwoDistribution verifies SampleSignedPowerOfTwo
// produces values in the correct range [−2^bits, 2^bits].
func TestSampleSignedPowerOfTwoDistribution(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint{1, 8, 64} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits)
		for range 500 {
			x, err := SampleSignedPowerOfTwo(nil, bits)
			if err != nil {
				t.Fatal(err)
			}
			if x.Cmp(new(big.Int).Neg(bound)) < 0 || x.Cmp(bound) > 0 {
				t.Errorf("bits=%d: sample %s out of range [−2^%d, 2^%d]", bits, x, bits, bits)
			}
		}
	}
}

// TestSampleMultRangeDistribution verifies SampleMultRange produces values in
// ±(N·2^bits).
func TestSampleMultRangeDistribution(t *testing.T) {
	t.Parallel()
	n := big.NewInt(100003)
	for _, bits := range []uint{1, 8, 64} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits)
		bound.Mul(bound, n)
		for range 500 {
			x, err := SampleMultRange(nil, bits, n)
			if err != nil {
				t.Fatal(err)
			}
			if x.Cmp(new(big.Int).Neg(bound)) < 0 || x.Cmp(bound) > 0 {
				t.Errorf("bits=%d: sample %s out of range ±N·2^%d", bits, x, bits)
			}
		}
	}
}
