package shamir

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
)

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

func TestLagrangeRejectsDuplicate(t *testing.T) {
	_, err := LagrangeCoefficient(1, []tss.PartyID{1, 1}, big.NewInt(101))
	if err == nil {
		t.Fatal("expected duplicate rejection")
	}
}
