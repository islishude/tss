package edwards25519

import (
	"bytes"
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

func TestScalarHelpersReturnIndependentScalars(t *testing.T) {
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
	if err := VerifyScalarShare(nil, 1, nil); err == nil {
		t.Fatal("VerifyScalarShare accepted nil scalar")
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

func TestPointFromBytesRejectsTorsionComponent(t *testing.T) {
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
