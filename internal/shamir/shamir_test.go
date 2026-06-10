package shamir

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// --- RandomScalar ---

func TestRandomScalarNilOrder(t *testing.T) {
	_, err := RandomScalar(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil order")
	}
}

func TestRandomScalarZeroOrder(t *testing.T) {
	_, err := RandomScalar(nil, big.NewInt(0))
	if err == nil {
		t.Fatal("expected error for zero order")
	}
}

func TestRandomScalarNegativeOrder(t *testing.T) {
	_, err := RandomScalar(nil, big.NewInt(-7))
	if err == nil {
		t.Fatal("expected error for negative order")
	}
}

func TestRandomScalarUsesCryptoRandWhenReaderNil(t *testing.T) {
	order := big.NewInt(101)
	x, err := RandomScalar(nil, order)
	if err != nil {
		t.Fatal(err)
	}
	if x.Sign() <= 0 || x.Cmp(order) >= 0 {
		t.Fatalf("RandomScalar out of range: %s", x)
	}
}

func TestRandomScalarDeterministic(t *testing.T) {
	order := big.NewInt(101)
	r := testutil.DeterministicReader(42)
	a, err := RandomScalar(r, order)
	if err != nil {
		t.Fatal(err)
	}
	r = testutil.DeterministicReader(42)
	b, err := RandomScalar(r, order)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cmp(b) != 0 {
		t.Fatalf("deterministic RandomScalar mismatch: %s vs %s", a, b)
	}
}

func TestRandomScalarNonZero(t *testing.T) {
	// With a small order, zero should never appear (loop retries).
	order := big.NewInt(2)
	for range 20 {
		x, err := RandomScalar(nil, order)
		if err != nil {
			t.Fatal(err)
		}
		if x.Sign() == 0 {
			t.Fatal("RandomScalar returned zero")
		}
	}
}

// --- RandomPolynomial ---

func TestRandomPolynomialZeroThreshold(t *testing.T) {
	_, err := RandomPolynomial(nil, big.NewInt(101), 0, nil)
	if err == nil {
		t.Fatal("expected error for zero threshold")
	}
}

func TestRandomPolynomialNegativeThreshold(t *testing.T) {
	_, err := RandomPolynomial(nil, big.NewInt(101), -1, nil)
	if err == nil {
		t.Fatal("expected error for negative threshold")
	}
}

func TestRandomPolynomialThresholdOneWithConstant(t *testing.T) {
	order := big.NewInt(101)
	coeffs, err := RandomPolynomial(nil, order, 1, big.NewInt(42))
	if err != nil {
		t.Fatal(err)
	}
	if len(coeffs) != 1 {
		t.Fatalf("expected 1 coefficient, got %d", len(coeffs))
	}
	if coeffs[0].Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("expected constant 42, got %s", coeffs[0])
	}
}

func TestRandomPolynomialThresholdOneWithoutConstant(t *testing.T) {
	order := big.NewInt(101)
	coeffs, err := RandomPolynomial(nil, order, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(coeffs) != 1 {
		t.Fatalf("expected 1 coefficient, got %d", len(coeffs))
	}
	if coeffs[0].Sign() == 0 || coeffs[0].Cmp(order) >= 0 {
		t.Fatalf("random constant out of range: %s", coeffs[0])
	}
}

func TestRandomPolynomialNormalizesConstant(t *testing.T) {
	order := big.NewInt(101)
	// 150 mod 101 = 49
	coeffs, err := RandomPolynomial(nil, order, 1, big.NewInt(150))
	if err != nil {
		t.Fatal(err)
	}
	if coeffs[0].Cmp(big.NewInt(49)) != 0 {
		t.Fatalf("constant not normalized: got %s, want 49", coeffs[0])
	}
}

func TestRandomPolynomialDeterministic(t *testing.T) {
	order := big.NewInt(101)
	constant := big.NewInt(7)
	r := testutil.DeterministicReader(42)
	a, err := RandomPolynomial(r, order, 3, constant)
	if err != nil {
		t.Fatal(err)
	}
	r = testutil.DeterministicReader(42)
	b, err := RandomPolynomial(r, order, 3, constant)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("length mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			t.Fatalf("coefficient %d mismatch: %s vs %s", i, a[i], b[i])
		}
	}
}

func TestRandomPolynomialCoefficientsInRange(t *testing.T) {
	order := big.NewInt(101)
	coeffs, err := RandomPolynomial(nil, order, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range coeffs {
		if c.Sign() == 0 {
			t.Fatalf("coefficient %d is zero", i)
		}
		if c.Cmp(order) >= 0 {
			t.Fatalf("coefficient %d >= order: %s", i, c)
		}
	}
}

// --- Eval ---

func TestEvalEmptyCoeffs(t *testing.T) {
	order := big.NewInt(101)
	result := Eval(nil, 1, order)
	if result.Sign() != 0 {
		t.Fatalf("empty coeffs should eval to 0, got %s", result)
	}
}

func TestEvalZeroID(t *testing.T) {
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}
	// f(0) = 42 (the constant term)
	result := Eval(coeffs, 0, order)
	if result.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("Eval at 0 should return constant: got %s, want 42", result)
	}
}

func TestEvalKnownPolynomial(t *testing.T) {
	// f(x) = 42 + 9x + 3x^2 mod 101
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}

	tests := []struct {
		id   tss.PartyID
		want int64
	}{
		{1, 54},  // 42 + 9 + 3 = 54
		{2, 72},  // 42 + 18 + 12 = 72
		{3, 96},  // 42 + 27 + 27 = 96
		{5, 61},  // 42 + 45 + 75 = 162 ≡ 61 mod 101
		{10, 28}, // 42 + 90 + 300 = 432 ≡ 28 mod 101
	}
	for _, tt := range tests {
		got := Eval(coeffs, tt.id, order)
		want := big.NewInt(tt.want)
		if got.Cmp(want) != 0 {
			t.Fatalf("Eval(coeffs, %d) = %s, want %s", tt.id, got, want)
		}
	}
}

func TestEvalLargeID(t *testing.T) {
	// f(x) = 5 + 2x mod 1009
	order := big.NewInt(1009)
	coeffs := []*big.Int{big.NewInt(5), big.NewInt(2)}
	// id := tss.PartyID(^uint32(0)) // max uint32
	id := tss.PartyID(4294967295)
	result := Eval(coeffs, id, order)
	// f(2^32-1) = 5 + 2*(2^32-1) = 5 + 2*4294967295 = 5 + 8589934590 = 8589934595
	// 8589934595 mod 1009 = ...
	expected := new(big.Int).SetUint64(uint64(id))
	expected.Mul(expected, big.NewInt(2))
	expected.Add(expected, big.NewInt(5))
	expected.Mod(expected, order)
	if result.Cmp(expected) != 0 {
		t.Fatalf("Eval with large ID: got %s, want %s", result, expected)
	}
}

// --- LagrangeCoefficient ---

func TestLagrangeCoefficientZeroID(t *testing.T) {
	_, err := LagrangeCoefficient(0, []tss.PartyID{1, 2, 3}, big.NewInt(101))
	if err == nil {
		t.Fatal("expected error for id=0")
	}
}

func TestLagrangeCoefficientZeroInSet(t *testing.T) {
	_, err := LagrangeCoefficient(1, []tss.PartyID{1, 0, 2}, big.NewInt(101))
	if err == nil {
		t.Fatal("expected error when set contains 0")
	}
}

func TestLagrangeCoefficientDuplicateInSet(t *testing.T) {
	_, err := LagrangeCoefficient(1, []tss.PartyID{1, 2, 2}, big.NewInt(101))
	if err == nil {
		t.Fatal("expected error for duplicate in set")
	}
}

func TestLagrangeCoefficientIDNotInSet(t *testing.T) {
	_, err := LagrangeCoefficient(3, []tss.PartyID{1, 2, 4}, big.NewInt(101))
	if err == nil {
		t.Fatal("expected error when id not in interpolation set")
	}
}

func TestLagrangeCoefficientNonInvertibleDenominator(t *testing.T) {
	// When PartyIDs are congruent mod order, diff = 0 and ModInverse fails.
	// Use order=5: id=1, other=6 → 6-1=5 ≡ 0 (mod 5).
	_, err := LagrangeCoefficient(1, []tss.PartyID{1, 6}, big.NewInt(5))
	if err == nil {
		t.Fatal("expected error for non-invertible denominator")
	}
}

func TestLagrangeCoefficientCorrectness(t *testing.T) {
	// For a 2-of-3 sharing over order=101:
	// f(x) = 42 + 9x, shares at 1, 2, 3.
	// Lagrange coefficient for point 1 among {1,2}:
	// λ₁ = 2/(2-1) = 2 (since x=2 is the other point)
	order := big.NewInt(101)
	lambda, err := LagrangeCoefficient(1, []tss.PartyID{1, 2}, order)
	if err != nil {
		t.Fatal(err)
	}
	// λ₁ = x₂ / (x₂ - x₁) = 2 / (2-1) = 2 mod 101
	if lambda.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("LagrangeCoefficient(1, {1,2}) = %s, want 2", lambda)
	}
}

func TestLagrangeCoefficientReconstructs(t *testing.T) {
	// 2-of-3 sharing over order=101: f(x) = 42 + 9x (degree 1, 2 coeffs).
	// Shares at 1, 2, 3. Any 2 shares should reconstruct 42.
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9)}
	shares := []Share{
		{ID: 1, Value: Eval(coeffs, 1, order)},
		{ID: 2, Value: Eval(coeffs, 2, order)},
		{ID: 3, Value: Eval(coeffs, 3, order)},
	}

	pairs := [][]tss.PartyID{
		{1, 2}, {2, 3}, {1, 3},
	}
	for _, pair := range pairs {
		lambda1, err := LagrangeCoefficient(pair[0], pair, order)
		if err != nil {
			t.Fatal(err)
		}
		lambda2, err := LagrangeCoefficient(pair[1], pair, order)
		if err != nil {
			t.Fatal(err)
		}
		reconstructed := new(big.Int).Mul(shares[pair[0]-1].Value, lambda1)
		reconstructed.Add(reconstructed, new(big.Int).Mul(shares[pair[1]-1].Value, lambda2))
		reconstructed.Mod(reconstructed, order)

		if reconstructed.Cmp(big.NewInt(42)) != 0 {
			t.Fatalf("reconstruction with {%d,%d} failed: got %s, want 42",
				pair[0], pair[1], reconstructed)
		}
	}
}

// --- InterpolateConstant ---

func TestInterpolateConstantEmptyShares(t *testing.T) {
	_, err := InterpolateConstant(nil, big.NewInt(101))
	if err == nil {
		t.Fatal("expected error for empty shares")
	}
}

func TestInterpolateConstantNilValue(t *testing.T) {
	shares := []Share{{ID: 1, Value: nil}}
	_, err := InterpolateConstant(shares, big.NewInt(101))
	if err == nil {
		t.Fatal("expected error for nil share value")
	}
}

func TestInterpolateConstant(t *testing.T) {
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}
	all := []Share{
		{ID: 1, Value: Eval(coeffs, 1, order)},
		{ID: 2, Value: Eval(coeffs, 2, order)},
		{ID: 5, Value: Eval(coeffs, 5, order)},
	}
	got, err := InterpolateConstant(all, order)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("constant = %s, want 42", got)
	}
}

func TestInterpolateConstantThreshold(t *testing.T) {
	// For a 2-of-5 sharing, any 2 shares should reconstruct.
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(7)} // degree 1
	allShares := []Share{
		{ID: 1, Value: Eval(coeffs, 1, order)},
		{ID: 2, Value: Eval(coeffs, 2, order)},
		{ID: 3, Value: Eval(coeffs, 3, order)},
		{ID: 4, Value: Eval(coeffs, 4, order)},
		{ID: 5, Value: Eval(coeffs, 5, order)},
	}

	// Try every pair.
	for i := range len(allShares) {
		for j := i + 1; j < len(allShares); j++ {
			subset := []Share{allShares[i], allShares[j]}
			got, err := InterpolateConstant(subset, order)
			if err != nil {
				t.Fatalf("subset {%d,%d}: %v", allShares[i].ID, allShares[j].ID, err)
			}
			if got.Cmp(big.NewInt(42)) != 0 {
				t.Fatalf("subset {%d,%d}: got %s, want 42",
					allShares[i].ID, allShares[j].ID, got)
			}
		}
	}
}

func TestInterpolateConstantAllShares(t *testing.T) {
	// Interpolating with all shares should also work (over-determined system).
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(7)}
	shares := []Share{
		{ID: 1, Value: Eval(coeffs, 1, order)},
		{ID: 2, Value: Eval(coeffs, 2, order)},
		{ID: 3, Value: Eval(coeffs, 3, order)},
	}
	got, err := InterpolateConstant(shares, order)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("got %s, want 42", got)
	}
}

// --- Normalize ---

func TestNormalizeInRange(t *testing.T) {
	order := big.NewInt(101)
	out := Normalize(big.NewInt(42), order)
	if out.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("Normalize(42) = %s, want 42", out)
	}
}

func TestNormalizeAboveRange(t *testing.T) {
	order := big.NewInt(101)
	out := Normalize(big.NewInt(150), order)
	if out.Cmp(big.NewInt(49)) != 0 { // 150 mod 101 = 49
		t.Fatalf("Normalize(150) = %s, want 49", out)
	}
}

func TestNormalizeNegative(t *testing.T) {
	order := big.NewInt(101)
	out := Normalize(big.NewInt(-5), order)
	if out.Cmp(big.NewInt(96)) != 0 { // -5 mod 101 = 96
		t.Fatalf("Normalize(-5) = %s, want 96", out)
	}
}

func TestNormalizeZero(t *testing.T) {
	order := big.NewInt(101)
	out := Normalize(big.NewInt(0), order)
	if out.Sign() != 0 {
		t.Fatalf("Normalize(0) = %s, want 0", out)
	}
}

func TestNormalizeExactMultiple(t *testing.T) {
	order := big.NewInt(101)
	out := Normalize(big.NewInt(202), order) // 2*101
	if out.Sign() != 0 {
		t.Fatalf("Normalize(202) = %s, want 0", out)
	}
}

// --- Add ---

func TestAddBasic(t *testing.T) {
	order := big.NewInt(101)
	out := Add(big.NewInt(30), big.NewInt(40), order)
	if out.Cmp(big.NewInt(70)) != 0 {
		t.Fatalf("30+40 mod 101 = %s, want 70", out)
	}
}

func TestAddWrap(t *testing.T) {
	order := big.NewInt(101)
	out := Add(big.NewInt(60), big.NewInt(50), order)
	if out.Cmp(big.NewInt(9)) != 0 { // 110 mod 101 = 9
		t.Fatalf("60+50 mod 101 = %s, want 9", out)
	}
}

// --- Sub ---

func TestSubBasic(t *testing.T) {
	order := big.NewInt(101)
	out := Sub(big.NewInt(70), big.NewInt(30), order)
	if out.Cmp(big.NewInt(40)) != 0 {
		t.Fatalf("70-30 mod 101 = %s, want 40", out)
	}
}

func TestSubWrap(t *testing.T) {
	order := big.NewInt(101)
	out := Sub(big.NewInt(10), big.NewInt(30), order)
	if out.Cmp(big.NewInt(81)) != 0 { // -20 mod 101 = 81
		t.Fatalf("10-30 mod 101 = %s, want 81", out)
	}
}

// --- Mul ---

func TestMulBasic(t *testing.T) {
	order := big.NewInt(101)
	out := Mul(big.NewInt(7), big.NewInt(11), order)
	if out.Cmp(big.NewInt(77)) != 0 {
		t.Fatalf("7*11 mod 101 = %s, want 77", out)
	}
}

func TestMulWrap(t *testing.T) {
	order := big.NewInt(101)
	out := Mul(big.NewInt(10), big.NewInt(20), order)
	if out.Cmp(big.NewInt(99)) != 0 { // 200 mod 101 = 200 - 101 = 99
		t.Fatalf("10*20 mod 101 = %s, want 99", out)
	}
}

func TestMulZero(t *testing.T) {
	order := big.NewInt(101)
	out := Mul(big.NewInt(0), big.NewInt(42), order)
	if out.Sign() != 0 {
		t.Fatalf("0*42 mod 101 = %s, want 0", out)
	}
}

// --- Roundtrip: full Shamir sharing flow ---

func TestFullSharingRoundtrip(t *testing.T) {
	order := big.NewInt(101)
	secret := big.NewInt(42)
	threshold := 3
	partyCount := 5

	coeffs, err := RandomPolynomial(nil, order, threshold, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(coeffs) != threshold {
		t.Fatalf("expected %d coefficients, got %d", threshold, len(coeffs))
	}

	// Generate shares for all parties.
	shares := make([]Share, partyCount)
	for i := range shares {
		id := tss.PartyID(i + 1)
		shares[i] = Share{ID: id, Value: Eval(coeffs, id, order)}
	}

	// Reconstruct with exactly threshold shares.
	got, err := InterpolateConstant(shares[:threshold], order)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("reconstructed = %s, want %s", got, secret)
	}
}

// --- Roundtrip: deterministic sharing ---

func TestDeterministicSharing(t *testing.T) {
	order := big.NewInt(101)

	r := testutil.DeterministicReader(42)
	coeffsA, err := RandomPolynomial(r, order, 3, nil)
	if err != nil {
		t.Fatal(err)
	}

	r = testutil.DeterministicReader(42)
	coeffsB, err := RandomPolynomial(r, order, 3, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := range coeffsA {
		if coeffsA[i].Cmp(coeffsB[i]) != 0 {
			t.Fatalf("non-deterministic coefficient %d: %s vs %s", i, coeffsA[i], coeffsB[i])
		}
	}
}

// --- Legacy tests (preserved) ---

func TestInterpolateConstantLegacy(t *testing.T) {
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}
	all := []Share{
		{ID: 1, Value: Eval(coeffs, 1, order)},
		{ID: 2, Value: Eval(coeffs, 2, order)},
		{ID: 5, Value: Eval(coeffs, 5, order)},
	}
	got, err := InterpolateConstant(all, order)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("constant = %s, want 42", got)
	}
}

func TestLagrangeRejectsDuplicate(t *testing.T) {
	_, err := LagrangeCoefficient(1, []tss.PartyID{1, 1}, big.NewInt(101))
	if err == nil {
		t.Fatal("expected duplicate rejection")
	}
}
