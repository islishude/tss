package paillier

import (
	"fmt"
	"math"
	"math/big"
	"testing"
)

// TestNewProofChallengeDistribution verifies that the 128-bit challenges
// produced by Transcript.ChallengeSigned are uniformly distributed.
func TestNewProofChallengeDistribution(t *testing.T) {
	t.Parallel()
	const nChallenges = 5000

	// Count bit frequencies across many challenges.
	bitCounts := make([]int, 128)

	for i := range nChallenges {
		transcript := NewTranscript("challenge-dist-test")
		transcript.AppendBytes("index", []byte{byte(i), byte(i >> 8), byte(i >> 16)})
		e, err := transcript.ChallengeSigned(128)
		if err != nil {
			t.Fatal(err)
		}
		if e.Sign() == 0 {
			t.Fatalf("iteration %d: zero challenge", i)
		}

		// Count bits. e is a 128-bit challenge so e.Bytes() returns at most 16 bytes.
		// We process each byte's bits independently, capped at 128 bit positions.
		eBytes := e.Bytes()
		for byteIdx := 0; byteIdx < len(eBytes) && byteIdx < 16; byteIdx++ {
			b := eBytes[len(eBytes)-1-byteIdx] // LSB first
			for bitIdx := 0; bitIdx < 8 && byteIdx*8+bitIdx < 128; bitIdx++ {
				if b&(1<<bitIdx) != 0 {
					bitCounts[byteIdx*8+bitIdx]++
				}
			}
		}
	}

	// Chi-squared test per bit.
	significant := 0
	for bitIdx, count := range bitCounts {
		expected := float64(nChallenges) / 2.0
		diff := float64(count) - expected
		chiSq := (diff * diff) / expected
		// With α=0.001 and 1 df, critical value ≈ 10.83.
		if chiSq > 10.83 {
			significant++
			t.Errorf("challenge bit %d: count=%d, expected=%.0f, χ²=%.2f",
				bitIdx, count, expected, chiSq)
		}
	}

	// With 128 bits and α=0.001, we expect ~0.13 false positives.
	if significant > 5 {
		t.Errorf("%d bits show significant deviation (expected ≤1)", significant)
	}
	t.Logf("ChallengeSigned distribution: %d challenges, %d/128 bits significant (α=0.001)",
		nChallenges, significant)
}

// TestChallengeSignedNoModularBias verifies that ChallengeSigned does NOT
// use modular reduction (which would create bias). Instead it uses bit masking.
// A challenge uniformly distributed in [0, 2^128) has exactly 64 expected 1-bits
// and 64 expected 0-bits, with no modular bias toward smaller values.
func TestChallengeSignedNoModularBias(t *testing.T) {
	t.Parallel()
	const nChallenges = 5000

	// If modular reduction were used (mod q), the most significant bits would
	// be biased toward 0. We check that the highest bit (bit 127) has ~50% 1-bits.
	highBitOnes := 0

	for i := range nChallenges {
		transcript := NewTranscript("no-mod-bias-test")
		transcript.AppendBytes("index", []byte{byte(i), byte(i >> 8), byte(i >> 16)})
		e, err := transcript.ChallengeSigned(128)
		if err != nil {
			t.Fatal(err)
		}
		// Check if the 128th bit is set.
		// e is up to 128 bits = 16 bytes. The most significant byte may be smaller.
		// Check the actual MSB using Bit().
		if e.Bit(127) == 1 {
			highBitOnes++
		}
	}

	expected := float64(nChallenges) / 2.0
	stdDev := math.Sqrt(float64(nChallenges) * 0.25)
	zScore := (float64(highBitOnes) - expected) / stdDev

	t.Logf("Bit 127 distribution: %d ones / %d (%.4f, z=%.2f)",
		highBitOnes, nChallenges, float64(highBitOnes)/float64(nChallenges), zScore)

	if math.Abs(zScore) > 5.0 {
		t.Errorf("Bit 127 shows modular bias: z=%.2f (>5σ)", zScore)
	}
}

// TestLegacyProofChallengeDistribution verifies that legacy challenge()
// produces uniformly distributed full-width SHA-256 challenges.
func TestLegacyProofChallengeDistribution(t *testing.T) {
	t.Parallel()
	const nChallenges = 5000

	// Generate challenges with different inputs.
	mean := new(big.Int)

	for i := range nChallenges {
		c := challenge([]byte("legacy dist test"), []byte{byte(i), byte(i >> 8)})
		mean.Add(mean, c)
	}

	// Expected mean for uniform values in [0, 2^256) is approximately 2^255.
	mean.Div(mean, big.NewInt(nChallenges))
	expected := new(big.Int).Lsh(big.NewInt(1), 255)

	// Compute |mean - expected| / expected as relative deviation.
	diff := new(big.Int).Sub(mean, expected)
	diff.Abs(diff)
	relDev := new(big.Int).Mul(diff, big.NewInt(1000000))
	relDev.Div(relDev, expected)

	t.Logf("Legacy challenge mean: %s (expected ~q/2 = %s)", mean, expected)
	t.Logf("Relative deviation: %d ppm", relDev.Int64())

	// For 5,000 uniform 256-bit samples, the sample mean has roughly 0.8%
	// relative standard deviation. A 5% bound catches gross bias without
	// treating ordinary sample variance as a protocol failure.
	if relDev.Cmp(big.NewInt(50000)) > 0 {
		t.Errorf("Legacy challenge mean deviates >50000 ppm from expected")
	}

	// Verify no zero challenges in 5000 samples (probability ≈ 5000/q ≈ 0).
	for i := range nChallenges {
		c := challenge([]byte("legacy zero check"), []byte{byte(i), byte(i >> 8)})
		if c.Sign() == 0 {
			t.Errorf("iteration %d: legacy challenge is zero (probability ~2^-256)", i)
		}
	}
}

// TestChallengeDistributionAcrossSessions verifies that challenges from
// different sessions (domains) produce independent challenge streams.
func TestChallengeDistributionAcrossSessions(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	const nSessions = 1000

	for i := range nSessions {
		transcript := NewTranscript(fmt.Sprintf("session-%d", i))
		transcript.AppendBytes("data", []byte("test"))
		e, err := transcript.ChallengeSigned(128)
		if err != nil {
			t.Fatal(err)
		}
		key := e.String()
		if seen[key] {
			t.Fatalf("session %d: challenge collision %s (extremely unlikely)", i, key)
		}
		seen[key] = true
	}
	t.Logf("%d sessions: no challenge collisions", nSessions)
}
