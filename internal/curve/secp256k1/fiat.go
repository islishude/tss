package secp256k1

import (
	"errors"
	"math/big"
	"slices"

	fiatfield "github.com/islishude/tss/internal/fiat/secp256k1field"
	fiatscalar "github.com/islishude/tss/internal/fiat/secp256k1scalar"
)

// Scalar is a secp256k1 subgroup scalar backed by fiat-crypto arithmetic.
type Scalar struct {
	mont fiatscalar.MontgomeryDomainFieldElement
}

// FieldElement is a secp256k1 base-field element backed by fiat-crypto arithmetic.
type FieldElement struct {
	mont fiatfield.MontgomeryDomainFieldElement
}

// ScalarFromCanonical parses a canonical non-zero secp256k1 scalar.
func ScalarFromCanonical(in []byte) (Scalar, error) {
	x, err := ParseScalar(in)
	if err != nil {
		return Scalar{}, err
	}
	return ScalarFromBig(x), nil
}

// ScalarFromBig returns x reduced modulo the secp256k1 subgroup order.
func ScalarFromBig(x *big.Int) Scalar {
	reduced := mod(x, N)
	var raw [32]uint8
	copy(raw[:], reverse32(bytesFixed(reduced, 32)))
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromBytes((*[4]uint64)(&nonMont), &raw)
	var out Scalar
	fiatscalar.ToMontgomery(&out.mont, &nonMont)
	return out
}

// Big returns s as a non-negative integer representative.
func (s Scalar) Big() *big.Int {
	return new(big.Int).SetBytes(s.Bytes())
}

// Bytes returns s as a fixed-width canonical big-endian scalar.
func (s Scalar) Bytes() []byte {
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromMontgomery(&nonMont, &s.mont)
	var raw [32]uint8
	fiatscalar.ToBytes(&raw, (*[4]uint64)(&nonMont))
	return reverse32(raw[:])
}

// IsZero reports whether s is zero.
func (s Scalar) IsZero() bool {
	var nz uint64
	fiatscalar.Nonzero(&nz, (*[4]uint64)(&s.mont))
	return nz == 0
}

// ScalarAdd returns a+b modulo the subgroup order.
func ScalarAdd(a, b Scalar) Scalar {
	var out Scalar
	fiatscalar.Add(&out.mont, &a.mont, &b.mont)
	return out
}

// ScalarSub returns a-b modulo the subgroup order.
func ScalarSub(a, b Scalar) Scalar {
	var out Scalar
	fiatscalar.Sub(&out.mont, &a.mont, &b.mont)
	return out
}

// ScalarMul returns a*b modulo the subgroup order.
func ScalarMul(a, b Scalar) Scalar {
	var out Scalar
	fiatscalar.Mul(&out.mont, &a.mont, &b.mont)
	return out
}

// ScalarNeg returns -a modulo the subgroup order.
func ScalarNeg(a Scalar) Scalar {
	var out Scalar
	fiatscalar.Opp(&out.mont, &a.mont)
	return out
}

// ScalarInvert returns a^-1 modulo the subgroup order.
func ScalarInvert(a Scalar) (Scalar, error) {
	if a.IsZero() {
		return Scalar{}, errors.New("zero scalar is not invertible")
	}
	inv := new(big.Int).ModInverse(a.Big(), N)
	if inv == nil {
		return Scalar{}, errors.New("scalar is not invertible")
	}
	return ScalarFromBig(inv), nil
}

// FieldElementFromCanonical parses a canonical secp256k1 base-field element.
func FieldElementFromCanonical(in []byte) (FieldElement, error) {
	if len(in) != 32 {
		return FieldElement{}, errors.New("secp256k1 field element must be 32 bytes")
	}
	x := new(big.Int).SetBytes(in)
	if x.Cmp(P) >= 0 {
		return FieldElement{}, errors.New("secp256k1 field element out of range")
	}
	return FieldElementFromBig(x), nil
}

// FieldElementFromBig returns x reduced modulo the secp256k1 base field.
func FieldElementFromBig(x *big.Int) FieldElement {
	reduced := mod(x, P)
	var raw [32]uint8
	copy(raw[:], reverse32(bytesFixed(reduced, 32)))
	var nonMont fiatfield.NonMontgomeryDomainFieldElement
	fiatfield.FromBytes((*[4]uint64)(&nonMont), &raw)
	var out FieldElement
	fiatfield.ToMontgomery(&out.mont, &nonMont)
	return out
}

// Big returns f as a non-negative integer representative.
func (f FieldElement) Big() *big.Int {
	return new(big.Int).SetBytes(f.Bytes())
}

// Bytes returns f as a fixed-width canonical big-endian field element.
func (f FieldElement) Bytes() []byte {
	var nonMont fiatfield.NonMontgomeryDomainFieldElement
	fiatfield.FromMontgomery(&nonMont, &f.mont)
	var raw [32]uint8
	fiatfield.ToBytes(&raw, (*[4]uint64)(&nonMont))
	return reverse32(raw[:])
}

// FieldAdd returns a+b modulo the base-field prime.
func FieldAdd(a, b FieldElement) FieldElement {
	var out FieldElement
	fiatfield.Add(&out.mont, &a.mont, &b.mont)
	return out
}

// FieldSub returns a-b modulo the base-field prime.
func FieldSub(a, b FieldElement) FieldElement {
	var out FieldElement
	fiatfield.Sub(&out.mont, &a.mont, &b.mont)
	return out
}

// FieldMul returns a*b modulo the base-field prime.
func FieldMul(a, b FieldElement) FieldElement {
	var out FieldElement
	fiatfield.Mul(&out.mont, &a.mont, &b.mont)
	return out
}

// FieldSquare returns a*a modulo the base-field prime.
func FieldSquare(a FieldElement) FieldElement {
	var out FieldElement
	fiatfield.Square(&out.mont, &a.mont)
	return out
}

// FieldNeg returns -a modulo the base-field prime.
func FieldNeg(a FieldElement) FieldElement {
	var out FieldElement
	fiatfield.Opp(&out.mont, &a.mont)
	return out
}

// FieldInvert returns a^-1 modulo the base-field prime.
func FieldInvert(a FieldElement) (FieldElement, error) {
	if a.Big().Sign() == 0 {
		return FieldElement{}, errors.New("zero field element is not invertible")
	}
	inv := new(big.Int).ModInverse(a.Big(), P)
	if inv == nil {
		return FieldElement{}, errors.New("field element is not invertible")
	}
	return FieldElementFromBig(inv), nil
}

func reverse32(in []byte) []byte {
	out := slices.Clone(in)
	for i := 0; i < len(out)/2; i++ {
		j := len(out) - 1 - i
		out[i], out[j] = out[j], out[i]
	}
	return out
}
