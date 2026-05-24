package edwards25519

import (
	"errors"
	"math/big"
	"slices"

	fiatscalar "github.com/islishude/tss/internal/fiat/ed25519scalar"
)

// Scalar is an Ed25519 subgroup scalar backed by fiat-crypto arithmetic.
type Scalar struct {
	mont fiatscalar.MontgomeryDomainFieldElement
}

// ScalarFromCanonicalFiat parses a canonical Ed25519 scalar into fiat form.
func ScalarFromCanonicalFiat(in []byte) (Scalar, error) {
	if len(in) != 32 {
		return Scalar{}, errors.New("edwards25519 scalar must be 32 bytes")
	}
	x := littleToBig(in)
	if x.Sign() == 0 || x.Cmp(order) >= 0 {
		return Scalar{}, errors.New("edwards25519 scalar out of range")
	}
	return FiatScalarFromBig(x), nil
}

// FiatScalarFromBig returns x reduced modulo the Ed25519 subgroup order.
func FiatScalarFromBig(x *big.Int) Scalar {
	n := new(big.Int).Mod(new(big.Int).Set(x), order)
	if n.Sign() < 0 {
		n.Add(n, order)
	}
	var raw [32]uint8
	copy(raw[:], bigToLittle(n, 32))
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromBytes((*[4]uint64)(&nonMont), &raw)
	var out Scalar
	fiatscalar.ToMontgomery(&out.mont, &nonMont)
	return out
}

// Big returns s as a non-negative integer representative.
func (s Scalar) Big() *big.Int {
	return littleToBig(s.Bytes())
}

// Bytes returns s as canonical little-endian scalar bytes.
func (s Scalar) Bytes() []byte {
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromMontgomery(&nonMont, &s.mont)
	var raw [32]uint8
	fiatscalar.ToBytes(&raw, (*[4]uint64)(&nonMont))
	return slices.Clone(raw[:])
}

// IsZero reports whether s is zero.
func (s Scalar) IsZero() bool {
	var nz uint64
	fiatscalar.Nonzero(&nz, (*[4]uint64)(&s.mont))
	return nz == 0
}

// ScalarAdd returns a+b modulo the Ed25519 subgroup order.
func ScalarAdd(a, b Scalar) Scalar {
	var out Scalar
	fiatscalar.Add(&out.mont, &a.mont, &b.mont)
	return out
}

// ScalarSub returns a-b modulo the Ed25519 subgroup order.
func ScalarSub(a, b Scalar) Scalar {
	var out Scalar
	fiatscalar.Sub(&out.mont, &a.mont, &b.mont)
	return out
}

// ScalarMul returns a*b modulo the Ed25519 subgroup order.
func ScalarMul(a, b Scalar) Scalar {
	var out Scalar
	fiatscalar.Mul(&out.mont, &a.mont, &b.mont)
	return out
}

// ScalarNeg returns -a modulo the Ed25519 subgroup order.
func ScalarNeg(a Scalar) Scalar {
	var out Scalar
	fiatscalar.Opp(&out.mont, &a.mont)
	return out
}
