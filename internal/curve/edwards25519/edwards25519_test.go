package edwards25519

import (
	"math/big"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/shamir"
)

func TestScalarFromBigOne(t *testing.T) {
	p, err := ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if p.Equal(fed.NewGeneratorPoint()) != 1 {
		t.Fatal("[1]B did not equal generator")
	}
}

func TestScalarAdditionMatchesPointAddition(t *testing.T) {
	a := big.NewInt(7)
	b := big.NewInt(11)
	ab := new(big.Int).Add(a, b)
	pA, err := ScalarBaseMultBig(a)
	if err != nil {
		t.Fatal(err)
	}
	pB, err := ScalarBaseMultBig(b)
	if err != nil {
		t.Fatal(err)
	}
	pAB, err := ScalarBaseMultBig(ab)
	if err != nil {
		t.Fatal(err)
	}
	got := AddPoints(pA, pB)
	if got.Equal(pAB) != 1 {
		t.Fatal("[a]B + [b]B != [a+b]B")
	}
}

func TestFiatScalarArithmeticMatchesBigInt(t *testing.T) {
	a := FiatScalarFromBig(big.NewInt(7))
	b := FiatScalarFromBig(big.NewInt(11))
	got := ScalarMul(ScalarAdd(a, b), b).Big()
	want := new(big.Int).Mul(big.NewInt(18), big.NewInt(11))
	want.Mod(want, Order())
	if got.Cmp(want) != 0 {
		t.Fatalf("fiat scalar arithmetic mismatch: got %s want %s", got, want)
	}
}

func TestVerifyShare(t *testing.T) {
	order := Order()
	coeffs, err := shamir.RandomPolynomial(nil, order, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	commitments := make([][]byte, len(coeffs))
	for i, coeff := range coeffs {
		p, err := ScalarBaseMultBig(coeff)
		if err != nil {
			t.Fatal(err)
		}
		commitments[i] = p.Bytes()
	}
	for id := uint32(1); id <= 5; id++ {
		share := shamir.Eval(coeffs, tss.PartyID(id), order)
		if err := VerifyShare(commitments, id, share); err != nil {
			t.Fatalf("id %d: %v", id, err)
		}
	}
}
