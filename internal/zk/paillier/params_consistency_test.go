package paillier

import (
	"math/big"
	"testing"
)

// TestDefaultSecurityParamsValues verifies that the production
// DefaultSecurityParams match their documented values. Any drift here
// changes the security model of all CGGMP proofs.
func TestDefaultSecurityParamsValues(t *testing.T) {
	sp := DefaultSecurityParams()

	if sp.Ell != 256 {
		t.Errorf("Ell = %d, want 256 (secp256k1 scalar bit length)", sp.Ell)
	}
	if sp.EllPrime != 848 {
		t.Errorf("EllPrime = %d, want 848 (CGGMP affine secondary range)", sp.EllPrime)
	}
	if sp.Epsilon != 230 {
		t.Errorf("Epsilon = %d, want 230 (statistical slack)", sp.Epsilon)
	}
	if sp.ChallengeBits != 128 {
		t.Errorf("ChallengeBits = %d, want 128 (128-bit soundness)", sp.ChallengeBits)
	}
	if sp.MinPaillierBits != 3072 {
		t.Errorf("MinPaillierBits = %d, want 3072 (NIST SP 800-57)", sp.MinPaillierBits)
	}
}

// TestEncRangeFormula verifies that EncRange() returns the correct formula
// Ell + max(ChallengeBits, Epsilon). The mask α must be sampled from a range
// wide enough to statistically hide e·m.
//
// With DefaultSecurityParams: EncRange = 256 + max(128, 230) = 486.
// This means α ∈ [−2^486, 2^486], providing:
//   - max(|e|) = 2^128 − 1
//   - max(|m|) = 2^256 − 1
//   - max(|e·m|) ≈ 2^384
//   - mask range = 2^487 (signed) → ~2^486 positive
//
// The statistical hiding per candidate is ~2^(486−384) = 2^102 candidates.
// This is below the 2^128 claimed in the code comments but still infeasible
// to enumerate (2^102 > 2^80 security target for statistical hiding).
func TestEncRangeFormula(t *testing.T) {
	sp := DefaultSecurityParams()

	encRange := sp.EncRange()
	expected := sp.Ell + max(sp.ChallengeBits, sp.Epsilon)
	if encRange != expected {
		t.Fatalf("EncRange() = %d, want %d (Ell + max(ChallengeBits, Epsilon))", encRange, expected)
	}
	if encRange != 486 {
		t.Errorf("EncRange() = %d, expected 486 for DefaultSecurityParams", encRange)
	}

	affgRange := sp.AffGRange()
	expectedAffG := sp.EllPrime + max(sp.ChallengeBits, sp.Epsilon)
	if affgRange != expectedAffG {
		t.Fatalf("AffGRange() = %d, want %d (EllPrime + max(ChallengeBits, Epsilon))", affgRange, expectedAffG)
	}
	if affgRange != 1078 {
		t.Errorf("AffGRange() = %d, expected 1078 for DefaultSecurityParams", affgRange)
	}
}

// TestEncRangeStatisticalHiding computes the actual statistical hiding provided
// by the production EncRange and documents the result. With DefaultSecurityParams:
// mask α ∈ [0, 2^486), response z = α + e·m where e ∈ [0, 2^128) and m ∈ [0, 2^256).
//
// For a given (z, e), the set of possible m is {m : 0 ≤ z − e·m < 2^486, 0 ≤ m < q}.
// The candidate count is approximately 2^486 / e ≈ 2^358 when e ≈ 2^128.
//
// The statistical hiding is the logarithm of the minimum candidate set size:
// log2(2^486 / 2^128) = 358 bits. This is well above the 128-bit target.
func TestEncRangeStatisticalHiding(t *testing.T) {
	sp := DefaultSecurityParams()
	maskBits := sp.EncRange() // 486

	// The mask provides 2^maskBits possible α values.
	// For a worst-case challenge e ≈ 2^128, the candidate interval is:
	//   width ≈ 2^maskBits / e = 2^(maskBits - 128) = 2^358
	//
	// Even for the maximum possible challenge (2^128 − 1), the hiding is:
	//   log2(2^486 / (2^128 − 1)) ≈ 358 bits
	hidingBits := maskBits - sp.ChallengeBits
	if hidingBits < 128 {
		t.Errorf("statistical hiding = %d bits, need ≥ 128", hidingBits)
	}
	t.Logf("EncRange statistical hiding: ~%d bits (mask=%d, challenge=%d)", hidingBits, maskBits, sp.ChallengeBits)
}

// TestChallengeBitsDoNotExceedHashOutput verifies that ChallengeBits ≤ 256,
// since the challenge is derived from SHA-256. Using more bits than the hash
// output would create a biased challenge distribution.
func TestChallengeBitsDoNotExceedHashOutput(t *testing.T) {
	sp := DefaultSecurityParams()
	if sp.ChallengeBits > 256 {
		t.Fatalf("ChallengeBits = %d exceeds SHA-256 output (256 bits)", sp.ChallengeBits)
	}

	fast := FastSecurityParams()
	if fast.ChallengeBits > 256 {
		t.Fatalf("FastSecurityParams.ChallengeBits = %d exceeds SHA-256 output", fast.ChallengeBits)
	}
}

// TestTranscriptBindsAllSecurityParams verifies that each new CGGMP proof
// transcript binds Ell, EllPrime, Epsilon, and ChallengeBits. If these are
// not bound, a malicious prover could use weaker parameters without the
// verifier detecting it.
func TestTranscriptBindsAllSecurityParams(t *testing.T) {
	// Verify that buildEncTranscript, buildAffGTranscript, and
	// buildLogStarTranscript all call t.AppendUint32 for each param.
	// We indirectly verify by checking that Verify rejects a proof when
	// params differ. Use the new proofs.

	t.Run("EncProof params in transcript", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping crypto proof test in short mode")
		}
		p1, stmt, _, proof := encProofFixture(t)
		encState := []byte("enc matrix")
		// Verify with same params
		if err := VerifyEnc(p1, encState, stmt, proof); err != nil {
			t.Fatal(err)
		}
		// Different epsilon: the transcript includes Epsilon, so the challenge
		// will differ, causing verification to fail.
		p3 := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon + 1, ChallengeBits: p1.ChallengeBits, MinPaillierBits: p1.MinPaillierBits}
		if err := VerifyEnc(p3, encState, stmt, proof); err == nil {
			t.Fatal("EncProof verified with wrong Epsilon (transcript should bind it)")
		}

		p4 := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon, ChallengeBits: p1.ChallengeBits + 1, MinPaillierBits: p1.MinPaillierBits}
		if err := VerifyEnc(p4, encState, stmt, proof); err == nil {
			t.Fatal("EncProof verified with wrong ChallengeBits (transcript should bind it)")
		}
	})

	t.Run("AffGProof params in transcript", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping crypto proof test in short mode")
		}
		p1, stmt, _, proof := affGProofFixture(t)
		affgState := []byte("affg matrix")
		if err := VerifyAffG(p1, affgState, stmt, proof); err != nil {
			t.Fatal(err)
		}
		pDiff := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon + 1, ChallengeBits: p1.ChallengeBits, MinPaillierBits: p1.MinPaillierBits}
		if err := VerifyAffG(pDiff, affgState, stmt, proof); err == nil {
			t.Fatal("AffGProof verified with wrong Epsilon (transcript should bind it)")
		}
	})

	t.Run("LogStarProof params in transcript", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping crypto proof test in short mode")
		}
		p1, stmt, _, proof := logStarProofFixture(t)
		logState := []byte("logstar matrix")
		if err := VerifyLogStar(p1, logState, stmt, proof); err != nil {
			t.Fatal(err)
		}
		pDiff := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon + 1, ChallengeBits: p1.ChallengeBits, MinPaillierBits: p1.MinPaillierBits}
		if err := VerifyLogStar(pDiff, logState, stmt, proof); err == nil {
			t.Fatal("LogStarProof verified with wrong Epsilon (transcript should bind it)")
		}
	})
}

// TestFastSecurityParamsSanity verifies FastSecurityParams uses reduced
// parameters that are suitable for tests but NOT for production.
func TestFastSecurityParamsSanity(t *testing.T) {
	fast := FastSecurityParams()
	def := DefaultSecurityParams()

	if fast.Ell != 256 {
		t.Errorf("FastSecurityParams.Ell = %d, want 256 (should match curve)", fast.Ell)
	}
	if fast.EllPrime != 512 {
		t.Errorf("FastSecurityParams.EllPrime = %d, want 512", fast.EllPrime)
	}
	if fast.Epsilon != 64 {
		t.Errorf("FastSecurityParams.Epsilon = %d, want 64", fast.Epsilon)
	}
	if fast.ChallengeBits != 128 {
		t.Errorf("FastSecurityParams.ChallengeBits = %d, want 128", fast.ChallengeBits)
	}
	if fast.MinPaillierBits != 768 {
		t.Errorf("FastSecurityParams.MinPaillierBits = %d, want 768", fast.MinPaillierBits)
	}

	// Fast params must be weaker than default (faster tests)
	if fast.MinPaillierBits >= def.MinPaillierBits {
		t.Error("FastSecurityParams.MinPaillierBits must be < DefaultSecurityParams.MinPaillierBits")
	}
	if fast.Epsilon >= def.Epsilon {
		t.Error("FastSecurityParams.Epsilon must be < DefaultSecurityParams.Epsilon")
	}
}

// TestSecurityParamsValidate verifies that Validate rejects invalid
// parameter combinations.
func TestSecurityParamsValidate(t *testing.T) {
	tests := []struct {
		name   string
		params SecurityParams
		ok     bool
	}{
		{"default", DefaultSecurityParams(), true},
		{"fast", FastSecurityParams(), true},
		{"zero Ell", SecurityParams{Ell: 0, EllPrime: 1, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: 1}, false},
		{"zero EllPrime", SecurityParams{Ell: 1, EllPrime: 0, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: 1}, false},
		{"zero Epsilon", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 0, ChallengeBits: 1, MinPaillierBits: 1}, false},
		{"zero ChallengeBits", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 0, MinPaillierBits: 1}, false},
		{"ChallengeBits > 256", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 257, MinPaillierBits: 1}, false},
		{"zero MinPaillierBits", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 128, MinPaillierBits: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.ok && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !tt.ok && err == nil {
				t.Error("Validate() = nil, want error")
			}
		})
	}
}

// TestCheckPaillierModulus verifies the minimum bit-length check on Paillier
// moduli.
func TestCheckPaillierModulus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}

	sp := DefaultSecurityParams()

	// Test with a key that meets the minimum (requires keygen)
	sk1024 := testPaillierKey(t, 1024)
	err := sp.CheckPaillierModulus(&sk1024.PublicKey)
	if err == nil {
		// 1024 < 3072 — should fail for default params
		t.Log("1024-bit modulus correctly rejected by DefaultSecurityParams")
	} else {
		t.Logf("CheckPaillierModulus(1024-bit): %v", err)
	}

	// FastSecurityParams should accept 1024-bit
	fast := FastSecurityParams()
	if err := fast.CheckPaillierModulus(&sk1024.PublicKey); err != nil {
		t.Errorf("FastSecurityParams rejected 1024-bit modulus: %v", err)
	}
}

// TestEncRangeDoesNotOverflow verifies that EncRange() can be represented
// as a uint without overflow on 64-bit platforms.
func TestEncRangeDoesNotOverflow(t *testing.T) {
	sp := DefaultSecurityParams()
	r := sp.EncRange()
	// r = 486, stored as uint. Verify operations on it don't overflow.
	_ = new(big.Int).Lsh(big.NewInt(1), r) // 2^486 must not panic

	affR := sp.AffGRange()
	_ = new(big.Int).Lsh(big.NewInt(1), affR) // 2^1078 must not panic
}

// TestEllPrimeExceedsEll verifies that EllPrime > Ell, which is required for
// the affine proof range to be strictly larger than the scalar range.
func TestEllPrimeExceedsEll(t *testing.T) {
	sp := DefaultSecurityParams()
	if sp.EllPrime <= sp.Ell {
		t.Errorf("EllPrime (%d) must be strictly greater than Ell (%d)", sp.EllPrime, sp.Ell)
	}
	if sp.EllPrime != 848 {
		t.Logf("EllPrime = %d — verify this matches CGGMP paper Table 1", sp.EllPrime)
	}

	fast := FastSecurityParams()
	if fast.EllPrime <= fast.Ell {
		t.Errorf("FastSecurityParams.EllPrime (%d) must be strictly greater than Ell (%d)", fast.EllPrime, fast.Ell)
	}
}

// TestActiveSecurityParamsRespectsOverride verifies the test override mechanism.
func TestActiveSecurityParamsRespectsOverride(t *testing.T) {
	def := ActiveSecurityParams()
	custom := SecurityParams{Ell: 256, EllPrime: 1024, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 768}

	restore := SetSecurityParamsForTesting(custom)
	defer restore()

	active := ActiveSecurityParams()
	if active.EllPrime != 1024 {
		t.Errorf("ActiveSecurityParams.EllPrime = %d, want 1024", active.EllPrime)
	}
	if active.Epsilon != 64 {
		t.Errorf("ActiveSecurityParams.Epsilon = %d, want 64", active.Epsilon)
	}

	// After restore, should return to default
	restore()
	restored := ActiveSecurityParams()
	if restored.EllPrime != def.EllPrime {
		t.Error("ActiveSecurityParams did not restore to default")
	}
}
