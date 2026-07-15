package edwards25519

import (
	"bytes"
	"math/big"
	"slices"
	"testing"

	fed "filippo.io/edwards25519"
)

func TestScalarFromBigOne(t *testing.T) {
	t.Parallel()
	p, err := ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if p.Equal(fed.NewGeneratorPoint()) != 1 {
		t.Fatal("[1]B did not equal generator")
	}
}

func TestScalarAdditionMatchesPointAddition(t *testing.T) {
	t.Parallel()
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

func TestScalarHelpersReturnIndependentScalars(t *testing.T) {
	t.Parallel()
	one := ScalarOne()
	one.Set(ScalarZero())
	if ScalarOne().Equal(fed.NewScalar()) == 1 {
		t.Fatal("ScalarOne returned shared mutable state")
	}
	if ScalarZero().Equal(fed.NewScalar()) != 1 {
		t.Fatal("ScalarZero did not return zero")
	}
}

func TestScalarConversionsReduceModuloOrder(t *testing.T) {
	t.Parallel()
	order := Order()
	x := new(big.Int).Add(order, big.NewInt(7))
	fromBig, err := ScalarFromBig(x)
	if err != nil {
		t.Fatal(err)
	}
	fromUint := ScalarFromUint64(7)
	if fromBig.Equal(fromUint) != 1 {
		t.Fatal("ScalarFromBig did not reduce modulo the subgroup order")
	}

	minusOne, err := ScalarFromBig(big.NewInt(-1))
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Sub(order, big.NewInt(1))
	if ScalarToBig(minusOne).Cmp(want) != 0 {
		t.Fatal("negative scalar reduction mismatch")
	}
}

func TestRandomScalarConsumesReaderAsBigEndian(t *testing.T) {
	t.Parallel()
	var sample [32]byte
	sample[31] = 7
	s, err := RandomScalar(bytes.NewReader(sample[:]))
	if err != nil {
		t.Fatal(err)
	}
	if ScalarToBig(s).Cmp(big.NewInt(7)) != 0 {
		t.Fatal("RandomScalar changed deterministic reader endianness")
	}
}

func TestVerifyScalarShareRejectsNilShare(t *testing.T) {
	t.Parallel()
	if err := VerifyScalarShare(nil, 1, nil); err == nil {
		t.Fatal("VerifyScalarShare accepted nil scalar")
	}
}

func evalBigPolynomial(coeffs []*big.Int, id uint32, order *big.Int) *big.Int {
	x := new(big.Int).SetUint64(uint64(id))
	acc := new(big.Int)
	for _, coeff := range slices.Backward(coeffs) {
		acc.Mul(acc, x)
		acc.Add(acc, coeff)
		acc.Mod(acc, order)
	}
	return acc
}

func TestVerifyShare(t *testing.T) {
	t.Parallel()
	order := Order()
	coeffs := []*big.Int{
		big.NewInt(42),
		big.NewInt(9),
		big.NewInt(3),
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
		share := evalBigPolynomial(coeffs, id, order)
		if err := VerifyShare(commitments, id, share); err != nil {
			t.Fatalf("id %d: %v", id, err)
		}
	}
}

func TestPointFromBytesRejectsTorsionComponent(t *testing.T) {
	t.Parallel()
	lowOrder, err := fed.NewIdentityPoint().SetBytes(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	mixed := AddPoints(fed.NewGeneratorPoint(), lowOrder)
	if _, err := PointFromBytes(mixed.Bytes()); err == nil {
		t.Fatal("point with torsion component should be rejected")
	}
	if _, err := PointFromBytesAllowIdentity(mixed.Bytes()); err == nil {
		t.Fatal("point with torsion component should be rejected even when identity is allowed")
	}
}

func TestPointFromBytesAllowIdentityRejectsNonCanonicalIdentity(t *testing.T) {
	t.Parallel()
	canonical := fed.NewIdentityPoint().Bytes()
	if _, err := PointFromBytesAllowIdentity(canonical); err != nil {
		t.Fatalf("canonical identity rejected: %v", err)
	}

	nonCanonical := bytes.Clone(canonical)
	nonCanonical[len(nonCanonical)-1] |= 0x80
	if _, err := PointFromBytesAllowIdentity(nonCanonical); err == nil {
		t.Fatal("non-canonical identity encoding was accepted")
	}
}
