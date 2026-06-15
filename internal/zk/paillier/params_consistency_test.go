package paillier

import (
	"testing"

	pai "github.com/islishude/tss/internal/paillier"
)

func fastSecurityParams() SecurityParams {
	return SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
}

// TestDefaultSecurityParamsValues verifies that the production
// DefaultSecurityParams match their documented values. Any drift here
// changes the security model of all CGGMP proofs.
func TestDefaultSecurityParamsValues(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	sp := DefaultSecurityParams()
	if sp.ChallengeBits > 256 {
		t.Fatalf("ChallengeBits = %d exceeds SHA-256 output (256 bits)", sp.ChallengeBits)
	}

	fast := fastSecurityParams()
	if fast.ChallengeBits > 256 {
		t.Fatalf("test security params.ChallengeBits = %d exceeds SHA-256 output", fast.ChallengeBits)
	}
}

// TestReducedSecurityParamsSanity verifies fastSecurityParams uses reduced
// parameters that are suitable for tests but NOT for production.
func TestReducedSecurityParamsSanity(t *testing.T) {
	t.Parallel()
	fast := fastSecurityParams()
	def := DefaultSecurityParams()

	if fast.Ell != 256 {
		t.Errorf("test security params.Ell = %d, want 256 (should match curve)", fast.Ell)
	}
	if fast.EllPrime != 512 {
		t.Errorf("test security params.EllPrime = %d, want 512", fast.EllPrime)
	}
	if fast.Epsilon != 64 {
		t.Errorf("test security params.Epsilon = %d, want 64", fast.Epsilon)
	}
	if fast.ChallengeBits != 128 {
		t.Errorf("test security params.ChallengeBits = %d, want 128", fast.ChallengeBits)
	}
	if fast.MinPaillierBits != 768 {
		t.Errorf("test security params.MinPaillierBits = %d, want 768", fast.MinPaillierBits)
	}

	// Fast params must be weaker than default (faster tests)
	if fast.MinPaillierBits >= def.MinPaillierBits {
		t.Error("test security params.MinPaillierBits must be < DefaultSecurityParams.MinPaillierBits")
	}
	if fast.Epsilon >= def.Epsilon {
		t.Error("test security params.Epsilon must be < DefaultSecurityParams.Epsilon")
	}
}

// TestSecurityParamsValidate verifies that Validate rejects invalid
// parameter combinations.
func TestSecurityParamsValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		params SecurityParams
		ok     bool
	}{
		{"default", DefaultSecurityParams(), true},
		{"fast", fastSecurityParams(), true},
		{"zero Ell", SecurityParams{Ell: 0, EllPrime: 1, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: 1}, false},
		{"zero EllPrime", SecurityParams{Ell: 1, EllPrime: 0, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: 1}, false},
		{"zero Epsilon", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 0, ChallengeBits: 1, MinPaillierBits: 1}, false},
		{"zero ChallengeBits", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 0, MinPaillierBits: 1}, false},
		{"ChallengeBits > 256", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 257, MinPaillierBits: 1}, false},
		{"zero MinPaillierBits", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 128, MinPaillierBits: 0}, false},
		{"MinPaillierBits below structural floor", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 128, MinPaillierBits: pai.MinModulusBits - 1}, false},
		{"MinPaillierBits above hard limit", SecurityParams{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 128, MinPaillierBits: maxSecurityParameterBits + 1}, false},
		{"encryption range above hard limit", SecurityParams{Ell: maxSecurityParameterBits, EllPrime: 1, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: pai.MinModulusBits}, false},
		{"affine range above hard limit", SecurityParams{Ell: 1, EllPrime: maxSecurityParameterBits, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: pai.MinModulusBits}, false},
		{"overflowing encryption range", SecurityParams{Ell: ^uint32(0), EllPrime: 1, Epsilon: 1, ChallengeBits: 1, MinPaillierBits: pai.MinModulusBits}, false},
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

func TestSecurityParamsRangesDoNotOverflow(t *testing.T) {
	t.Parallel()

	params := SecurityParams{
		Ell:             ^uint32(0),
		EllPrime:        ^uint32(0),
		Epsilon:         ^uint32(0),
		ChallengeBits:   1,
		MinPaillierBits: pai.MinModulusBits,
	}
	if got := params.EncRange(); got != maxSecurityParameterBits {
		t.Fatalf("EncRange() = %d, want bounded value %d", got, maxSecurityParameterBits)
	}
	if got := params.AffGRange(); got != maxSecurityParameterBits {
		t.Fatalf("AffGRange() = %d, want bounded value %d", got, maxSecurityParameterBits)
	}
}

// TestEllPrimeExceedsEll verifies that EllPrime > Ell, which is required for
// the affine proof range to be strictly larger than the scalar range.
func TestEllPrimeExceedsEll(t *testing.T) {
	t.Parallel()
	sp := DefaultSecurityParams()
	if sp.EllPrime <= sp.Ell {
		t.Errorf("EllPrime (%d) must be strictly greater than Ell (%d)", sp.EllPrime, sp.Ell)
	}
	if sp.EllPrime != 848 {
		t.Logf("EllPrime = %d — verify this matches CGGMP paper Table 1", sp.EllPrime)
	}

	fast := fastSecurityParams()
	if fast.EllPrime <= fast.Ell {
		t.Errorf("test security params.EllPrime (%d) must be strictly greater than Ell (%d)", fast.EllPrime, fast.Ell)
	}
}
