package shamir

import (
	"errors"
	"io"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

var errTestReader = errors.New("test reader failure")

type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) {
	return 0, errTestReader
}

var _ io.Reader = failingReader{}

func TestRandomPolynomialRejectsInvalidThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		threshold int
	}{
		{name: "zero", threshold: 0},
		{name: "negative", threshold: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := RandomPolynomial(nil, tc.threshold, nil); err == nil {
				t.Fatal("expected invalid threshold error")
			}
		})
	}
}

func TestRandomPolynomialUsesProvidedConstant(t *testing.T) {
	t.Parallel()

	constant := secp.ScalarZero()
	poly, err := RandomPolynomial(testutil.DeterministicReader(1), 3, &constant)
	if err != nil {
		t.Fatal(err)
	}
	if len(poly) != 3 {
		t.Fatalf("got %d coefficients, want 3", len(poly))
	}
	if !poly[0].Equal(constant) {
		t.Fatal("constant term was not preserved")
	}
	if poly[1].IsZero() || poly[2].IsZero() {
		t.Fatal("expected non-zero random non-constant coefficients")
	}
}

func TestRandomPolynomialSamplesNonZeroConstantWhenAbsent(t *testing.T) {
	t.Parallel()

	poly, err := RandomPolynomial(testutil.DeterministicReader(2), 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(poly) != 2 {
		t.Fatalf("got %d coefficients, want 2", len(poly))
	}
	if poly[0].IsZero() {
		t.Fatal("expected sampled constant term to be non-zero")
	}
	if poly[1].IsZero() {
		t.Fatal("expected sampled non-constant coefficient to be non-zero")
	}
}

func TestRandomPolynomialDeterministicForSameReaderSeed(t *testing.T) {
	t.Parallel()

	left, err := RandomPolynomial(testutil.DeterministicReader(3), 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := RandomPolynomial(testutil.DeterministicReader(3), 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != len(right) {
		t.Fatalf("polynomial lengths differ: %d != %d", len(left), len(right))
	}
	for i := range left {
		assertScalarEqual(t, left[i], right[i], "coefficient mismatch")
	}
}

func TestRandomPolynomialPropagatesReaderError(t *testing.T) {
	t.Parallel()

	if _, err := RandomPolynomial(failingReader{}, 1, nil); !errors.Is(err, errTestReader) {
		t.Fatalf("got error %v, want %v", err, errTestReader)
	}
}

func TestRandomPolynomialDoesNotReadWhenThresholdOneConstantProvided(t *testing.T) {
	t.Parallel()

	constant := secp.ScalarFromUint64(42)
	poly, err := RandomPolynomial(failingReader{}, 1, &constant)
	if err != nil {
		t.Fatal(err)
	}
	if len(poly) != 1 {
		t.Fatalf("got %d coefficients, want 1", len(poly))
	}
	assertScalarEqual(t, poly[0], constant, "constant term mismatch")
}

func TestEvalEmptyPolynomialReturnsZero(t *testing.T) {
	t.Parallel()

	if got := Eval(nil, 7); !got.IsZero() {
		t.Fatal("empty polynomial should evaluate to zero")
	}
}

func TestEvalAtZeroReturnsConstant(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	assertScalarEqual(t, Eval(poly, 0), secp.ScalarFromUint64(42), "constant term mismatch")
}

func TestEvalKnownPolynomial(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	tests := []struct {
		id   tss.PartyID
		want secp.Scalar
	}{
		{id: 1, want: secp.ScalarFromUint64(54)},
		{id: 2, want: secp.ScalarFromUint64(72)},
		{id: 3, want: secp.ScalarFromUint64(96)},
		{id: 5, want: secp.ScalarFromUint64(162)},
		{id: 99, want: secp.ScalarFromUint64(30336)},
	}
	for _, tc := range tests {
		t.Run("party", func(t *testing.T) {
			t.Parallel()

			assertScalarEqual(t, Eval(poly, tc.id), tc.want, "evaluation mismatch")
		})
	}
}

func TestEvalUsesScalarFieldModuloOrder(t *testing.T) {
	t.Parallel()

	poly := Polynomial{
		secp.ScalarNeg(secp.ScalarOne()),
		secp.ScalarOne(),
	}
	if got := Eval(poly, 1); !got.IsZero() {
		t.Fatal("expected (-1 + 1) mod order to be zero")
	}
	assertScalarEqual(t, Eval(poly, 2), secp.ScalarOne(), "modular evaluation mismatch")
}

func TestLagrangeCoefficientKnownTwoPartySet(t *testing.T) {
	t.Parallel()

	ids := tss.NewPartySet(1, 2)
	lambda1 := mustLagrangeCoefficient(t, 1, ids)
	lambda2 := mustLagrangeCoefficient(t, 2, ids)

	assertScalarEqual(t, lambda1, secp.ScalarFromUint64(2), "lambda_1 mismatch")
	assertScalarEqual(t, lambda2, secp.ScalarNeg(secp.ScalarOne()), "lambda_2 mismatch")
}

func TestLagrangeCoefficientKnownThreePartySet(t *testing.T) {
	t.Parallel()

	ids := tss.NewPartySet(1, 2, 3)

	assertScalarEqual(t, mustLagrangeCoefficient(t, 1, ids), secp.ScalarFromUint64(3), "lambda_1 mismatch")
	assertScalarEqual(t, mustLagrangeCoefficient(t, 2, ids), secp.ScalarNeg(secp.ScalarFromUint64(3)), "lambda_2 mismatch")
	assertScalarEqual(t, mustLagrangeCoefficient(t, 3, ids), secp.ScalarOne(), "lambda_3 mismatch")
}

func TestLagrangeCoefficientOrderInvariant(t *testing.T) {
	t.Parallel()

	left := mustLagrangeCoefficient(t, 3, tss.NewPartySet(1, 3, 5))
	right := mustLagrangeCoefficient(t, 3, tss.NewPartySet(5, 1, 3))

	assertScalarEqual(t, left, right, "interpolation coefficient should not depend on set order")
}

func TestLagrangeCoefficientReconstructsConstantAcrossSubsets(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	shares := map[tss.PartyID]secp.Scalar{
		1: Eval(poly, 1),
		2: Eval(poly, 2),
		3: Eval(poly, 3),
		4: Eval(poly, 4),
		5: Eval(poly, 5),
	}
	subsets := []tss.PartySet{
		tss.NewPartySet(1, 2, 3),
		tss.NewPartySet(1, 3, 5),
		tss.NewPartySet(2, 4, 5),
		tss.NewPartySet(5, 2, 4),
	}
	for _, subset := range subsets {
		t.Run("subset", func(t *testing.T) {
			t.Parallel()

			got := reconstructConstant(t, shares, subset)
			assertScalarEqual(t, got, poly[0], "reconstructed constant mismatch")
		})
	}
}

func TestLagrangeCoefficientRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   tss.PartyID
		ids  tss.PartySet
	}{
		{name: "zero id", id: 0, ids: tss.NewPartySet(1, 2)},
		{name: "zero in set", id: 1, ids: tss.PartySet{0, 1}},
		{name: "duplicate", id: 1, ids: tss.PartySet{1, 2, 2}},
		{name: "duplicate target", id: 1, ids: tss.PartySet{1, 1}},
		{name: "missing id", id: 3, ids: tss.NewPartySet(1, 2)},
		{name: "empty set", id: 1, ids: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := LagrangeCoefficient(tc.id, tc.ids); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFeldmanCommitmentsMatchEvaluatedShares(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	commitments := make([]*secp.Point, len(poly))
	for i, coeff := range poly {
		commitments[i] = secp.ScalarBaseMult(coeff)
	}

	for _, id := range tss.NewPartySet(1, 2, 3, 5) {
		t.Run("valid share", func(t *testing.T) {
			t.Parallel()

			share := Eval(poly, id)
			if err := secp.VerifySharePoints(commitments, id, share); err != nil {
				t.Fatalf("valid share rejected: %v", err)
			}
		})
	}

	badShare := secp.ScalarAdd(Eval(poly, 2), secp.ScalarOne())
	if err := secp.VerifySharePoints(commitments, 2, badShare); err == nil {
		t.Fatal("expected tampered share rejection")
	}
}

func TestRefreshZeroConstantReconstructsZero(t *testing.T) {
	t.Parallel()

	zero := secp.ScalarZero()
	poly, err := RandomPolynomial(testutil.DeterministicReader(4), 3, &zero)
	if err != nil {
		t.Fatal(err)
	}

	shares := map[tss.PartyID]secp.Scalar{
		1: Eval(poly, 1),
		2: Eval(poly, 2),
		3: Eval(poly, 3),
		4: Eval(poly, 4),
		5: Eval(poly, 5),
	}
	got := reconstructConstant(t, shares, tss.NewPartySet(1, 3, 5))
	if !got.IsZero() {
		t.Fatal("expected zero-constant refresh polynomial to reconstruct zero")
	}
}

func knownPolynomial() Polynomial {
	return Polynomial{
		secp.ScalarFromUint64(42),
		secp.ScalarFromUint64(9),
		secp.ScalarFromUint64(3),
	}
}

func reconstructConstant(t *testing.T, shares map[tss.PartyID]secp.Scalar, ids tss.PartySet) secp.Scalar {
	t.Helper()

	acc := secp.ScalarZero()
	for _, id := range ids {
		share, ok := shares[id]
		if !ok {
			t.Fatalf("missing share for party %d", id)
		}
		lambda := mustLagrangeCoefficient(t, id, ids)
		acc = secp.ScalarAdd(acc, secp.ScalarMul(share, lambda))
	}
	return acc
}

func mustLagrangeCoefficient(t *testing.T, id tss.PartyID, ids tss.PartySet) secp.Scalar {
	t.Helper()

	out, err := LagrangeCoefficient(id, ids)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertScalarEqual(t *testing.T, got, want secp.Scalar, msg string) {
	t.Helper()

	if !got.Equal(want) {
		t.Fatal(msg)
	}
}
