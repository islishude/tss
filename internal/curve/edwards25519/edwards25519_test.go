package edwards25519

import (
	"bytes"
	"math/big"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss/internal/shamir"
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

func TestVerifyShare(t *testing.T) {
	t.Parallel()
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
		share := shamir.Eval(coeffs, id, order)
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

func TestWirePointRoundTripAndIdentityPolicy(t *testing.T) {
	t.Parallel()
	generator := fed.NewGeneratorPoint()
	encoded, err := (WirePoint{P: generator}).MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, generator.Bytes()) {
		t.Fatal("WirePoint changed canonical point bytes")
	}
	var decoded WirePoint
	if err := decoded.UnmarshalWireValue(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.P.Equal(generator) != 1 {
		t.Fatal("WirePoint round trip mismatch")
	}
	if _, err := (WirePoint{}).MarshalWireValue(); err == nil {
		t.Fatal("WirePoint accepted nil marshal")
	}

	identity := fed.NewIdentityPoint()
	if _, err := (WirePoint{P: identity}).MarshalWireValue(); err == nil {
		t.Fatal("WirePoint accepted identity")
	}
	identityEncoded, err := (WirePointAllowIdentity{P: identity}).MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	var identityDecoded WirePointAllowIdentity
	if err := identityDecoded.UnmarshalWireValue(identityEncoded); err != nil {
		t.Fatal(err)
	}
	if !IsIdentity(identityDecoded.P) {
		t.Fatal("WirePointAllowIdentity did not preserve identity")
	}
}

func TestWirePointRejectsMalformedAndTorsionPoints(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 31, 33} {
		var point WirePoint
		if err := point.UnmarshalWireValue(make([]byte, size)); err == nil {
			t.Fatalf("WirePoint accepted %d-byte input", size)
		}
		var allowIdentity WirePointAllowIdentity
		if err := allowIdentity.UnmarshalWireValue(make([]byte, size)); err == nil {
			t.Fatalf("WirePointAllowIdentity accepted %d-byte input", size)
		}
	}

	lowOrder, err := fed.NewIdentityPoint().SetBytes(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	mixed := AddPoints(fed.NewGeneratorPoint(), lowOrder).Bytes()
	var point WirePoint
	if err := point.UnmarshalWireValue(mixed); err == nil {
		t.Fatal("WirePoint accepted a torsion component")
	}
	var allowIdentity WirePointAllowIdentity
	if err := allowIdentity.UnmarshalWireValue(mixed); err == nil {
		t.Fatal("WirePointAllowIdentity accepted a torsion component")
	}
}

func TestWireScalarRoundTrip(t *testing.T) {
	t.Parallel()
	scalar := ScalarFromUint64(7)
	encoded, err := (WireScalar{S: scalar}).MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	var decoded WireScalar
	if err := decoded.UnmarshalWireValue(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.S.Equal(scalar) != 1 {
		t.Fatal("WireScalar round trip mismatch")
	}
	if _, err := (WireScalar{}).MarshalWireValue(); err == nil {
		t.Fatal("WireScalar accepted nil marshal")
	}
}
