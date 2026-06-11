package shamir

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// --- RandomScalar ---

func TestRandomScalarRejectsInvalidOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		order *big.Int
	}{
		{"nil order", nil},
		{"zero order", big.NewInt(0)},
		{"negative order", big.NewInt(-7)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := RandomScalar(nil, tc.order)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRandomScalarUsesCryptoRandWhenReaderNil(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestRandomPolynomialRejectsInvalidThreshold(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		threshold int
	}{
		{"zero threshold", 0},
		{"negative threshold", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := RandomPolynomial(nil, big.NewInt(101), tc.threshold, nil)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRandomPolynomialThresholdOneWithConstant(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	order := big.NewInt(101)
	result := Eval(nil, 1, order)
	if result.Sign() != 0 {
		t.Fatalf("empty coeffs should eval to 0, got %s", result)
	}
}

func TestEvalZeroID(t *testing.T) {
	t.Parallel()
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}
	// f(0) = 42 (the constant term)
	result := Eval(coeffs, 0, order)
	if result.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("Eval at 0 should return constant: got %s, want 42", result)
	}
}

func TestEvalKnownPolynomial(t *testing.T) {
	t.Parallel()
	// f(x) = 42 + 9x + 3x^2 mod 101
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}

	tests := []struct {
		name string
		id   tss.PartyID
		want int64
	}{
		{name: "party 1", id: 1, want: 54},   // 42 + 9 + 3 = 54
		{name: "party 2", id: 2, want: 72},   // 42 + 18 + 12 = 72
		{name: "party 3", id: 3, want: 96},   // 42 + 27 + 27 = 96
		{name: "party 5", id: 5, want: 61},   // 42 + 45 + 75 = 162 ≡ 61 mod 101
		{name: "party 10", id: 10, want: 28}, // 42 + 90 + 300 = 432 ≡ 28 mod 101
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Eval(coeffs, tt.id, order)
			want := big.NewInt(tt.want)
			if got.Cmp(want) != 0 {
				t.Fatalf("Eval(coeffs, %d) = %s, want %s", tt.id, got, want)
			}
		})
	}
}

func TestEvalLargeID(t *testing.T) {
	t.Parallel()
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

func TestLagrangeCoefficientRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		id    tss.PartyID
		set   []tss.PartyID
		order int64
	}{
		{"id is zero", 0, []tss.PartyID{1, 2, 3}, 101},
		{"set contains zero", 1, []tss.PartyID{1, 0, 2}, 101},
		{"duplicate in set", 1, []tss.PartyID{1, 2, 2}, 101},
		{"id not in set", 3, []tss.PartyID{1, 2, 4}, 101},
		{"non-invertible denominator", 1, []tss.PartyID{1, 6}, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LagrangeCoefficient(tc.id, tc.set, big.NewInt(tc.order))
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLagrangeCoefficientCorrectness(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	// 2-of-3 sharing over order=101: f(x) = 42 + 9x (degree 1, 2 coeffs).
	// Shares at 1, 2, 3. Any 2 shares should reconstruct 42.
	order := big.NewInt(101)
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9)}
	shares := []Share{
		{ID: 1, Value: Eval(coeffs, 1, order)},
		{ID: 2, Value: Eval(coeffs, 2, order)},
		{ID: 3, Value: Eval(coeffs, 3, order)},
	}

	pairs := []struct {
		name string
		ids  []tss.PartyID
	}{
		{name: "{1,2}", ids: []tss.PartyID{1, 2}},
		{name: "{2,3}", ids: []tss.PartyID{2, 3}},
		{name: "{1,3}", ids: []tss.PartyID{1, 3}},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lambda1, err := LagrangeCoefficient(tc.ids[0], tc.ids, order)
			if err != nil {
				t.Fatal(err)
			}
			lambda2, err := LagrangeCoefficient(tc.ids[1], tc.ids, order)
			if err != nil {
				t.Fatal(err)
			}
			reconstructed := new(big.Int).Mul(shares[tc.ids[0]-1].Value, lambda1)
			reconstructed.Add(reconstructed, new(big.Int).Mul(shares[tc.ids[1]-1].Value, lambda2))
			reconstructed.Mod(reconstructed, order)

			if reconstructed.Cmp(big.NewInt(42)) != 0 {
				t.Fatalf("reconstruction failed: got %s, want 42", reconstructed)
			}
		})
	}
}

// --- InterpolateConstant ---

func TestInterpolateConstantRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		shares []Share
	}{
		{"empty shares", nil},
		{"nil share value", []Share{{ID: 1, Value: nil}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := InterpolateConstant(tc.shares, big.NewInt(101))
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestInterpolateConstant(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestNormalize(t *testing.T) {
	t.Parallel()
	order := big.NewInt(101)
	tests := []struct {
		name  string
		input int64
		want  int64
	}{
		{"in range", 42, 42},
		{"above range", 150, 49}, // 150 mod 101 = 49
		{"negative", -5, 96},     // -5 mod 101 = 96
		{"zero", 0, 0},
		{"exact multiple", 202, 0}, // 2*101 ≡ 0 mod 101
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := Normalize(big.NewInt(tc.input), order)
			if out.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("Normalize(%d) = %s, want %d", tc.input, out, tc.want)
			}
		})
	}
}

func TestAdd(t *testing.T) {
	t.Parallel()
	order := big.NewInt(101)
	tests := []struct {
		name string
		a, b int64
		want int64
	}{
		{"basic", 30, 40, 70},
		{"wrap", 60, 50, 9}, // 110 mod 101 = 9
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := Add(big.NewInt(tc.a), big.NewInt(tc.b), order)
			if out.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("%d+%d mod 101 = %s, want %d", tc.a, tc.b, out, tc.want)
			}
		})
	}
}

func TestSub(t *testing.T) {
	t.Parallel()
	order := big.NewInt(101)
	tests := []struct {
		name string
		a, b int64
		want int64
	}{
		{"basic", 70, 30, 40},
		{"wrap", 10, 30, 81}, // -20 mod 101 = 81
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := Sub(big.NewInt(tc.a), big.NewInt(tc.b), order)
			if out.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("%d-%d mod 101 = %s, want %d", tc.a, tc.b, out, tc.want)
			}
		})
	}
}

func TestMul(t *testing.T) {
	t.Parallel()
	order := big.NewInt(101)
	tests := []struct {
		name string
		a, b int64
		want int64
	}{
		{"basic", 7, 11, 77},
		{"wrap", 10, 20, 99}, // 200 mod 101 = 99
		{"zero", 0, 42, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := Mul(big.NewInt(tc.a), big.NewInt(tc.b), order)
			if out.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("%d*%d mod 101 = %s, want %d", tc.a, tc.b, out, tc.want)
			}
		})
	}
}

// --- Roundtrip: full Shamir sharing flow ---

func TestFullSharingRoundtrip(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
