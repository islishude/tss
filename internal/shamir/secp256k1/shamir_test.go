package secp256k1

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/testutil"
)

func TestRandomPolynomialRejectsInvalidThreshold(t *testing.T) {
	t.Parallel()

	if _, err := RandomPolynomial(nil, 0, nil); err == nil {
		t.Fatal("expected invalid threshold error")
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
	if !poly[0].IsZero() {
		t.Fatal("constant term was not preserved")
	}
	if poly[1].IsZero() || poly[2].IsZero() {
		t.Fatal("random non-constant coefficient was zero")
	}
}

func TestEvalMatchesGenericShamir(t *testing.T) {
	t.Parallel()

	coeffs := []*big.Int{big.NewInt(42), big.NewInt(9), big.NewInt(3)}
	poly := Polynomial{
		secp.ScalarFromBigInt(coeffs[0]),
		secp.ScalarFromBigInt(coeffs[1]),
		secp.ScalarFromBigInt(coeffs[2]),
	}
	for _, id := range []tss.PartyID{0, 1, 2, 5, 99} {
		got := Eval(poly, id).BigInt()
		want := shamir.Eval(coeffs, id, secp.Order())
		if got.Cmp(want) != 0 {
			t.Fatalf("Eval(id=%d) mismatch", id)
		}
	}
}

func TestLagrangeCoefficientMatchesGenericShamir(t *testing.T) {
	t.Parallel()

	ids := tss.NewPartySet(1, 2, 5)
	for _, id := range ids {
		got := mustLagrangeCoefficient(t, id, ids).BigInt()
		want, err := shamir.LagrangeCoefficient(id, ids, secp.Order())
		if err != nil {
			t.Fatal(err)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("LagrangeCoefficient(id=%d) mismatch", id)
		}
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
		{name: "missing id", id: 3, ids: tss.NewPartySet(1, 2)},
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

func mustLagrangeCoefficient(t *testing.T, id tss.PartyID, ids tss.PartySet) secp.Scalar {
	t.Helper()
	out, err := LagrangeCoefficient(id, ids)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
