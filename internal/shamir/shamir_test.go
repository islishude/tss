package shamir

import (
	"bytes"
	"errors"
	"io"
	"testing"

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

	for _, tc := range []struct {
		name      string
		threshold int
	}{
		{name: "zero", threshold: 0},
		{name: "negative", threshold: -1},
	} {
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

func TestEvalAtEmptyPolynomialReturnsZero(t *testing.T) {
	t.Parallel()

	if got := mustEvalAt(t, nil, identifierFromUint64(t, 7)); !got.IsZero() {
		t.Fatal("empty polynomial should evaluate to zero")
	}
}

func TestEvalAtRejectsZeroIdentifier(t *testing.T) {
	t.Parallel()

	if _, err := EvalAt(knownPolynomial(), Identifier{}); err == nil {
		t.Fatal("zero identifier accepted")
	}
}

func TestEvalAtConstantPolynomialReturnsConstant(t *testing.T) {
	t.Parallel()

	constant := secp.ScalarFromUint64(42)
	got := mustEvalAt(t, Polynomial{constant}, identifierFromUint64(t, 11))
	assertScalarEqual(t, got, constant, "constant term mismatch")
}

func TestEvalAtKnownPolynomial(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	for _, tc := range []struct {
		name string
		x    uint64
		want secp.Scalar
	}{
		{name: "one", x: 1, want: secp.ScalarFromUint64(54)},
		{name: "two", x: 2, want: secp.ScalarFromUint64(72)},
		{name: "three", x: 3, want: secp.ScalarFromUint64(96)},
		{name: "five", x: 5, want: secp.ScalarFromUint64(162)},
		{name: "ninety-nine", x: 99, want: secp.ScalarFromUint64(30336)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mustEvalAt(t, poly, identifierFromUint64(t, tc.x))
			assertScalarEqual(t, got, tc.want, "evaluation mismatch")
		})
	}
}

func TestEvalAtUsesScalarFieldModuloOrder(t *testing.T) {
	t.Parallel()

	poly := Polynomial{secp.ScalarNeg(secp.ScalarOne()), secp.ScalarOne()}
	if got := mustEvalAt(t, poly, identifierFromUint64(t, 1)); !got.IsZero() {
		t.Fatal("expected (-1 + 1) mod order to be zero")
	}
	got := mustEvalAt(t, poly, identifierFromUint64(t, 2))
	assertScalarEqual(t, got, secp.ScalarOne(), "modular evaluation mismatch")
}

func TestEvalAtUsesExplicitScalarIdentifier(t *testing.T) {
	t.Parallel()

	got := mustEvalAt(t, knownPolynomial(), identifierFromUint64(t, 11))
	// 42 + 9*11 + 3*11^2 = 504.
	assertScalarEqual(t, got, secp.ScalarFromUint64(504), "explicit identifier evaluation mismatch")
}

func TestIdentifierFromBytesRejectsZeroAndNonCanonicalValues(t *testing.T) {
	t.Parallel()

	valid := identifierFromUint64(t, 19)
	first := valid.Bytes()
	first[0] ^= 0xff
	if bytes.Equal(first, valid.Bytes()) {
		t.Fatal("Shamir identifier encoding aliases internal state")
	}
	if _, err := IdentifierFromBytes(make([]byte, secp.ScalarSize)); err == nil {
		t.Fatal("zero Shamir identifier accepted")
	}
	if _, err := IdentifierFromBytes(make([]byte, secp.ScalarSize-1)); err == nil {
		t.Fatal("short Shamir identifier accepted")
	}
	if _, err := IdentifierFromBytes(bytes.Repeat([]byte{0xff}, secp.ScalarSize)); err == nil {
		t.Fatal("out-of-range Shamir identifier accepted")
	}
}

func TestLagrangeCoefficientAtKnownTwoIdentifierSet(t *testing.T) {
	t.Parallel()

	ids := identifiersFromUint64(t, 1, 2)
	lambda1 := mustLagrangeCoefficientAt(t, ids[0], ids)
	lambda2 := mustLagrangeCoefficientAt(t, ids[1], ids)
	assertScalarEqual(t, lambda1, secp.ScalarFromUint64(2), "lambda_1 mismatch")
	assertScalarEqual(t, lambda2, secp.ScalarNeg(secp.ScalarOne()), "lambda_2 mismatch")
}

func TestLagrangeCoefficientAtKnownThreeIdentifierSet(t *testing.T) {
	t.Parallel()

	ids := identifiersFromUint64(t, 1, 2, 3)
	assertScalarEqual(t, mustLagrangeCoefficientAt(t, ids[0], ids), secp.ScalarFromUint64(3), "lambda_1 mismatch")
	assertScalarEqual(t, mustLagrangeCoefficientAt(t, ids[1], ids), secp.ScalarNeg(secp.ScalarFromUint64(3)), "lambda_2 mismatch")
	assertScalarEqual(t, mustLagrangeCoefficientAt(t, ids[2], ids), secp.ScalarOne(), "lambda_3 mismatch")
}

func TestLagrangeCoefficientAtOrderInvariant(t *testing.T) {
	t.Parallel()

	leftIDs := identifiersFromUint64(t, 1, 3, 5)
	rightIDs := []Identifier{leftIDs[2], leftIDs[0], leftIDs[1]}
	left := mustLagrangeCoefficientAt(t, leftIDs[1], leftIDs)
	right := mustLagrangeCoefficientAt(t, leftIDs[1], rightIDs)
	assertScalarEqual(t, left, right, "interpolation coefficient should not depend on set order")
}

func TestLagrangeCoefficientAtReconstructsConstantAcrossSubsets(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	identifiers := identifiersFromUint64(t, 1, 2, 3, 4, 5)
	shares := sharesAtIdentifiers(t, poly, identifiers)
	for _, subset := range [][]Identifier{
		{identifiers[0], identifiers[1], identifiers[2]},
		{identifiers[0], identifiers[2], identifiers[4]},
		{identifiers[1], identifiers[3], identifiers[4]},
		{identifiers[4], identifiers[1], identifiers[3]},
	} {
		got := reconstructConstantAt(t, shares, subset)
		assertScalarEqual(t, got, poly[0], "reconstructed constant mismatch")
	}
}

func TestLagrangeCoefficientAtRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	one := identifierFromUint64(t, 1)
	two := identifierFromUint64(t, 2)
	three := identifierFromUint64(t, 3)
	for _, tc := range []struct {
		name   string
		target Identifier
		ids    []Identifier
	}{
		{name: "zero target", target: Identifier{}, ids: []Identifier{one, two}},
		{name: "zero in set", target: one, ids: []Identifier{Identifier{}, one}},
		{name: "duplicate", target: one, ids: []Identifier{one, two, two}},
		{name: "duplicate target", target: one, ids: []Identifier{one, one}},
		{name: "missing target", target: three, ids: []Identifier{one, two}},
		{name: "empty set", target: one, ids: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := LagrangeCoefficientAt(tc.target, tc.ids); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLagrangeCoefficientAtReconstructsAcrossDynamicIdentifierSubsets(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	identifiers := identifiersFromUint64(t, 11, 17, 23, 29, 31)
	shares := sharesAtIdentifiers(t, poly, identifiers)
	for _, subset := range [][]Identifier{
		{identifiers[0], identifiers[1], identifiers[2]},
		{identifiers[0], identifiers[2], identifiers[4]},
		{identifiers[4], identifiers[1], identifiers[3]},
	} {
		got := reconstructConstantAt(t, shares, subset)
		assertScalarEqual(t, got, poly[0], "dynamic identifier reconstruction mismatch")
	}
}

func TestLagrangeCoefficientAtRejectsZeroCollisionAndMissingTarget(t *testing.T) {
	t.Parallel()

	one := identifierFromUint64(t, 11)
	two := identifierFromUint64(t, 17)
	missing := identifierFromUint64(t, 23)
	if _, err := LagrangeCoefficientAt(Identifier{}, []Identifier{Identifier{}, one}); err == nil {
		t.Fatal("zero dynamic identifier accepted")
	}
	if _, err := LagrangeCoefficientAt(one, []Identifier{one, two, two}); err == nil {
		t.Fatal("duplicate dynamic identifier accepted")
	}
	if _, err := LagrangeCoefficientAt(missing, []Identifier{one, two}); err == nil {
		t.Fatal("missing target dynamic identifier accepted")
	}
}

func TestFeldmanCommitmentsMatchSharesEvaluatedAtIdentifiers(t *testing.T) {
	t.Parallel()

	poly := knownPolynomial()
	commitments := make([]*secp.Point, len(poly))
	for i, coefficient := range poly {
		commitments[i] = secp.ScalarBaseMult(coefficient)
	}
	for _, identifier := range identifiersFromUint64(t, 1, 2, 3, 5) {
		share := mustEvalAt(t, poly, identifier)
		if err := verifyCommittedShareAtIdentifier(commitments, identifier, share); err != nil {
			t.Fatalf("valid share rejected: %v", err)
		}
	}
	two := identifierFromUint64(t, 2)
	badShare := secp.ScalarAdd(mustEvalAt(t, poly, two), secp.ScalarOne())
	if err := verifyCommittedShareAtIdentifier(commitments, two, badShare); err == nil {
		t.Fatal("expected tampered share rejection")
	}
}

func TestRefreshZeroConstantReconstructsZeroAtIdentifiers(t *testing.T) {
	t.Parallel()

	zero := secp.ScalarZero()
	poly, err := RandomPolynomial(testutil.DeterministicReader(4), 3, &zero)
	if err != nil {
		t.Fatal(err)
	}
	identifiers := identifiersFromUint64(t, 1, 2, 3, 4, 5)
	shares := sharesAtIdentifiers(t, poly, identifiers)
	got := reconstructConstantAt(t, shares, []Identifier{identifiers[0], identifiers[2], identifiers[4]})
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

func identifierFromUint64(t testing.TB, value uint64) Identifier {
	t.Helper()
	return mustIdentifier(t, secp.ScalarFromUint64(value).Bytes())
}

func identifiersFromUint64(t testing.TB, values ...uint64) []Identifier {
	t.Helper()
	out := make([]Identifier, len(values))
	for i, value := range values {
		out[i] = identifierFromUint64(t, value)
	}
	return out
}

func mustEvalAt(t testing.TB, poly Polynomial, identifier Identifier) secp.Scalar {
	t.Helper()
	out, err := EvalAt(poly, identifier)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func identifierKey(identifier Identifier) [secp.ScalarSize]byte {
	raw := identifier.Bytes()
	defer clear(raw)
	var key [secp.ScalarSize]byte
	copy(key[:], raw)
	return key
}

func sharesAtIdentifiers(t testing.TB, poly Polynomial, identifiers []Identifier) map[[secp.ScalarSize]byte]secp.Scalar {
	t.Helper()
	out := make(map[[secp.ScalarSize]byte]secp.Scalar, len(identifiers))
	for _, identifier := range identifiers {
		out[identifierKey(identifier)] = mustEvalAt(t, poly, identifier)
	}
	return out
}

func reconstructConstantAt(t testing.TB, shares map[[secp.ScalarSize]byte]secp.Scalar, identifiers []Identifier) secp.Scalar {
	t.Helper()
	accumulator := secp.ScalarZero()
	for _, identifier := range identifiers {
		share, ok := shares[identifierKey(identifier)]
		if !ok {
			t.Fatal("missing share for identifier")
		}
		lambda := mustLagrangeCoefficientAt(t, identifier, identifiers)
		accumulator = secp.ScalarAdd(accumulator, secp.ScalarMul(share, lambda))
	}
	return accumulator
}

func mustLagrangeCoefficientAt(t testing.TB, identifier Identifier, identifiers []Identifier) secp.Scalar {
	t.Helper()
	out, err := LagrangeCoefficientAt(identifier, identifiers)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func verifyCommittedShareAtIdentifier(commitments []*secp.Point, identifier Identifier, share secp.Scalar) error {
	if err := identifier.Validate(); err != nil {
		return err
	}
	left := secp.ScalarBaseMult(share)
	right := secp.NewInfinity()
	power := secp.ScalarOne()
	for _, commitment := range commitments {
		if commitment != nil {
			right = secp.Add(right, secp.ScalarMult(commitment, power))
		}
		power = secp.ScalarMul(power, identifier.scalar)
	}
	if !secp.Equal(left, right) {
		return errors.New("share does not match commitments at identifier")
	}
	return nil
}

func assertScalarEqual(t testing.TB, got, want secp.Scalar, message string) {
	t.Helper()
	if !got.Equal(want) {
		t.Fatal(message)
	}
}

func mustIdentifier(t testing.TB, raw []byte) Identifier {
	t.Helper()
	id, err := IdentifierFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
