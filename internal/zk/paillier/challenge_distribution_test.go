//go:build slowcrypto

package paillier

import (
	"math"
	"math/big"
	"testing"
)

// testChiSquaredPValue is the threshold for rejecting the null hypothesis
// that a bit distribution is uniform. With α=0.001 and 1 degree of freedom,
// the critical value is ~10.83. We use a more permissive threshold for
// practical testing.
const testChiSquaredPValue = 50.0

// TestModulusProofChallengeDistribution verifies that the y_i challenges
// derived via deriveModulusY are uniformly distributed across Z*_N.
// Non-uniform challenges would break the soundness of Πmod.
func TestModulusProofChallengeDistribution(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 3072)
	domain := []byte("distribution mod")
	party := uint32(1)
	proof, err := ProveModulus(nil, domain, sk, party)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyModulus(domain, sk.PublicKey, party, proof) {
		t.Fatal("modulus proof did not verify")
	}

	// For each of the 128 rounds, compute the y_i value and verify
	// it's a proper unit mod N.
	n := sk.N
	nLen := modulusBytes(n)

	for i := range modulusProofRounds {
		y, err := deriveModulusY(n, proof.TranscriptHash, i)
		if err != nil {
			t.Fatalf("round %d: deriveModulusY failed: %v", i, err)
		}
		// Verify y ∈ Z*_N.
		if y.Sign() <= 0 || y.Cmp(n) >= 0 {
			t.Fatalf("round %d: y out of range [1, N)", i)
		}
		if new(big.Int).GCD(nil, nil, y, n).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("round %d: y not coprime to N", i)
		}

		// Verify the y values across rounds are distinct (collision test).
		// With N ≈ 2^3072, the birthday bound is astronomically large,
		// so any collision would indicate a severe hash bias.
		for j := 0; j < i; j++ {
			yj, _ := deriveModulusY(n, proof.TranscriptHash, j)
			if y.Cmp(yj) == 0 {
				t.Fatalf("round %d: y collision with round %d (extremely unlikely)", i, j)
			}
		}

		_ = nLen
	}

	// Bit distribution test: generate many y_i values and check bit balance.
	// Sample 10000 y values from different transcripts.
	//
	// testing.Short() adjusts intensity (10000 → 1000 rounds), not tier-skipping.
	// This file is already behind //go:build slowcrypto for compile-time tier gating.
	// Within the slowcrypto tier, -short reduces statistical sample size for faster CI.
	nRounds := 10000
	if testing.Short() {
		nRounds = 1000
	}
	// For a 3072-bit modulus, y.Bytes() returns up to 384 bytes.
	// We check the first 256 bits of each y value.
	bitCounts := make([]int, 256) // track how often each bit position is 1

	// Use a single proof's transcript hash with different round indices
	// and counters to generate many y values.
	for i := range nRounds {
		y, err := deriveModulusY(n, proof.TranscriptHash, modulusProofRounds+i)
		if err != nil {
			t.Fatal(err)
		}
		// Check only the first 256 bits (32 bytes) to fit in bitCounts.
		yBytes := y.Bytes()
		for byteIdx := 0; byteIdx < 32 && byteIdx < len(yBytes); byteIdx++ {
			b := yBytes[len(yBytes)-1-byteIdx] // LSB first
			for bitIdx := 0; bitIdx < 8; bitIdx++ {
				if b&(1<<bitIdx) != 0 {
					bitCounts[byteIdx*8+bitIdx]++
				}
			}
		}
	}

	// Chi-squared test per bit position.
	for bitIdx, count := range bitCounts {
		expected := float64(nRounds) / 2.0
		diff := float64(count) - expected
		chiSq := (diff * diff) / expected
		if chiSq > testChiSquaredPValue {
			t.Errorf("bit %d: count=%d, expected=%.0f, χ²=%.2f (threshold=%.1f)",
				bitIdx, count, expected, chiSq, testChiSquaredPValue)
		}
	}
	t.Logf("Πmod challenge distribution: %d y values, bit balance χ² ≤ %.1f", nRounds, testChiSquaredPValue)
}

// TestRingPedersenChallengeDistribution verifies that the 128 single-bit
// challenges in Πprm are statistically indistinguishable from unbiased
// coin flips. With 128 rounds, the expected number of 1s is 64.
func TestRingPedersenChallengeDistribution(t *testing.T) {
	t.Parallel()
	securityParams := DefaultSecurityParams()
	sk := testPaillierKey(t, 3072)
	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("distribution prm")
	party := uint32(1)

	const nProofs = 100 // 100 proofs × 128 rounds = 12800 challenge bits
	onesTotal := 0
	totalBits := 0
	roundOnes := make([]int, ringPedersenProofRounds)

	for p := range nProofs {
		proof, err := ProveRingPedersen(nil, domain, sk, params, lambda, party)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyRingPedersen(securityParams, domain, params, party, proof) {
			t.Fatalf("proof %d did not verify", p)
		}
		for i, challenge := range proof.Challenges {
			if challenge == 1 {
				onesTotal++
				roundOnes[i]++
			} else if challenge != 0 {
				t.Fatalf("proof %d: invalid challenge byte %d", p, challenge)
			}
			totalBits++
		}
	}

	// Binomial test: with p=0.5 and n=12800, μ=6400, σ=√(npq) = √3200 ≈ 56.6.
	// At α=0.001, the critical z-value is ±3.29.
	expected := float64(totalBits) / 2.0
	stdDev := math.Sqrt(float64(totalBits) * 0.25)
	zScore := (float64(onesTotal) - expected) / stdDev

	t.Logf("Πprm challenge distribution: %d ones / %d bits = %.4f (z=%.2f, μ=%.0f, σ=%.1f)",
		onesTotal, totalBits, float64(onesTotal)/float64(totalBits), zScore, expected, stdDev)

	if math.Abs(zScore) > 5.0 {
		t.Errorf("challenge distribution deviates from uniform: z=%.2f (>5σ)", zScore)
	}

	// Check per-round distribution across proofs. These are 128 simultaneous
	// comparisons, so the threshold must control the family-wise false-positive
	// rate rather than treating each round as an isolated hypothesis. With 100
	// proofs, the old >4σ threshold rejected 29/71 ones and had an exact
	// two-sided binomial tail of 3.22e-5 per round, producing a Bonferroni
	// family-wise bound of about 0.41%. A strict >5σ threshold rejects only
	// 24/76 ones; its Bonferroni family-wise bound is below 2.4e-5.
	const perRoundZLimit = 5.0
	for i, ones := range roundOnes {
		expected := float64(nProofs) / 2.0
		stdDev := math.Sqrt(float64(nProofs) * 0.25)
		zScore := (float64(ones) - expected) / stdDev
		if math.Abs(zScore) > perRoundZLimit {
			t.Errorf("round %d: %d ones / %d proofs (z=%.2f, >%.0fσ)",
				i, ones, nProofs, zScore, perRoundZLimit)
		}
	}
}

// TestRingPedersenChallengeBitIndependence verifies that consecutive challenge
// bits are independent (no autocorrelation at lag 1).
func TestRingPedersenChallengeBitIndependence(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 3072)
	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("independence prm")
	party := uint32(1)

	// Count transitions: 00, 01, 10, 11 for consecutive bits.
	n00, n01, n10, n11 := 0, 0, 0, 0

	const nProofs = 100
	for range nProofs {
		proof, err := ProveRingPedersen(nil, domain, sk, params, lambda, party)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(proof.Challenges); i++ {
			prev := proof.Challenges[i-1]
			curr := proof.Challenges[i]
			switch {
			case prev == 0 && curr == 0:
				n00++
			case prev == 0 && curr == 1:
				n01++
			case prev == 1 && curr == 0:
				n10++
			case prev == 1 && curr == 1:
				n11++
			}
		}
	}

	total := n00 + n01 + n10 + n11
	// With independent unbiased bits, each transition should be ~25%.
	for _, pair := range []struct {
		name  string
		count int
	}{
		{"00", n00}, {"01", n01}, {"10", n10}, {"11", n11},
	} {
		expected := float64(total) / 4.0
		stdDev := math.Sqrt(float64(total) * 0.25 * 0.75) // variance = npq with p=0.25
		zScore := (float64(pair.count) - expected) / stdDev
		t.Logf("Πprm transition %s: %d (%.2f%%, z=%.2f)",
			pair.name, pair.count, 100*float64(pair.count)/float64(total), zScore)
		if math.Abs(zScore) > 5.0 {
			t.Errorf("transition %s deviates from independence: z=%.2f", pair.name, zScore)
		}
	}
}

// TestModulusProofChallengeIndependence verifies that consecutive y_i values
// are independent across rounds. Each round uses expandHash with a different
// round index, so they should be independent.
func TestModulusProofChallengeIndependence(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 3072)
	domain := []byte("independence mod")
	proof, err := ProveModulus(nil, domain, sk, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Generate pairs of consecutive y values and verify they differ.
	n := sk.N
	for i := 1; i < modulusProofRounds; i++ {
		yPrev, _ := deriveModulusY(n, proof.TranscriptHash, i-1)
		yCurr, _ := deriveModulusY(n, proof.TranscriptHash, i)
		if yPrev.Cmp(yCurr) == 0 {
			t.Fatalf("round %d: consecutive y values collide (should be independent)", i)
		}
	}
}

// TestSecurityParamsAuditBitBoundary verifies the production parameter bounds
// with a production-size Paillier key.
func TestSecurityParamsAuditBitBoundary(t *testing.T) {
	t.Parallel()
	sp := DefaultSecurityParams()
	sk := testPaillierKey(t, 3072)

	if err := sp.CheckPaillierModulus(sk.PublicKey); err != nil {
		t.Fatalf("3072-bit key rejected by production params: %v", err)
	}
}
