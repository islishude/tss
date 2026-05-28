package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

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

// Precomputed modulus bytes in little-endian for canonical validation.
var (
	scalarModulusLE = mustModulusLE("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	fieldModulusLE  = mustModulusLE("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
)

func mustModulusLE(hex string) [32]byte {
	x, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("invalid hex constant")
	}
	b := x.Bytes()
	var out [32]byte
	for i := range b {
		out[31-i] = b[len(b)-1-i]
	}
	return out
}

// ScalarFromBytes parses a canonical 32-byte big-endian non-zero scalar.
func ScalarFromBytes(in []byte) (Scalar, error) {
	if len(in) != 32 {
		return Scalar{}, errors.New("secp256k1 scalar must be 32 bytes")
	}
	if isZero32(in) {
		return Scalar{}, errors.New("secp256k1 scalar is zero")
	}
	var le [32]uint8
	reverse32To(&le, in)
	if !lt32LE(le, scalarModulusLE) {
		return Scalar{}, errors.New("secp256k1 scalar out of range")
	}
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromBytes((*[4]uint64)(&nonMont), &le)
	var out Scalar
	fiatscalar.ToMontgomery(&out.mont, &nonMont)
	return out, nil
}

// Bytes returns s as a fixed-width canonical big-endian scalar.
func (s Scalar) Bytes() []byte {
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromMontgomery(&nonMont, &s.mont)
	var raw [32]uint8
	fiatscalar.ToBytes(&raw, (*[4]uint64)(&nonMont))
	out := make([]byte, 32)
	reverse32To((*[32]uint8)(out), raw[:])
	return out
}

// IsZero reports whether s is zero.
func (s Scalar) IsZero() bool {
	var nz uint64
	fiatscalar.Nonzero(&nz, (*[4]uint64)(&s.mont))
	return nz == 0
}

// Equal reports whether s and t are the same scalar.
func (s Scalar) Equal(t Scalar) bool {
	return s.mont == t.mont
}

// Set copies t into s.
func (s *Scalar) Set(t Scalar) {
	s.mont = t.mont
}

// BigInt returns s as a *big.Int for shamir compatibility only.
func (s Scalar) BigInt() *big.Int {
	return new(big.Int).SetBytes(s.Bytes())
}

// ScalarZero returns the zero scalar.
func ScalarZero() Scalar {
	return Scalar{}
}

// ScalarOne returns the scalar 1 in Montgomery domain.
func ScalarOne() Scalar {
	var out Scalar
	fiatscalar.SetOne(&out.mont)
	return out
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

// ScalarSquare returns a*a modulo the subgroup order.
func ScalarSquare(a Scalar) Scalar {
	var out Scalar
	fiatscalar.Square(&out.mont, &a.mont)
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
	return scalarInvAddchain(a), nil
}

// FieldElementFromBytes parses a canonical 32-byte big-endian field element.
func FieldElementFromBytes(in []byte) (FieldElement, error) {
	if len(in) != 32 {
		return FieldElement{}, errors.New("secp256k1 field element must be 32 bytes")
	}
	var le [32]uint8
	reverse32To(&le, in)
	if !lt32LE(le, fieldModulusLE) {
		return FieldElement{}, errors.New("secp256k1 field element out of range")
	}
	var nonMont fiatfield.NonMontgomeryDomainFieldElement
	fiatfield.FromBytes((*[4]uint64)(&nonMont), &le)
	var out FieldElement
	fiatfield.ToMontgomery(&out.mont, &nonMont)
	return out, nil
}

// Bytes returns f as a fixed-width canonical big-endian field element.
func (f FieldElement) Bytes() []byte {
	var nonMont fiatfield.NonMontgomeryDomainFieldElement
	fiatfield.FromMontgomery(&nonMont, &f.mont)
	var raw [32]uint8
	fiatfield.ToBytes(&raw, (*[4]uint64)(&nonMont))
	out := make([]byte, 32)
	reverse32To((*[32]uint8)(out), raw[:])
	return out
}

// IsZero reports whether f is zero.
func (f FieldElement) IsZero() bool {
	var nz uint64
	fiatfield.Nonzero(&nz, (*[4]uint64)(&f.mont))
	return nz == 0
}

// Equal reports whether f and g represent the same field element.
func (f FieldElement) Equal(g FieldElement) bool {
	return f.mont == g.mont
}

// Set copies g into f.
func (f *FieldElement) Set(g FieldElement) {
	f.mont = g.mont
}

// BigInt returns f as a *big.Int for compatibility.
func (f FieldElement) BigInt() *big.Int {
	return new(big.Int).SetBytes(f.Bytes())
}

// lowSOrder returns N/2 as a Scalar for low-S checks.
// Precomputed at init time.
var halfOrderVar Scalar

func init() {
	halfOrderVar = scalarFromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
}

func halfOrder() Scalar {
	return halfOrderVar
}

func scalarFromHex(s string) Scalar {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex constant")
	}
	b := x.Bytes()
	pad := make([]byte, 32)
	copy(pad[32-len(b):], b)
	out, err := ScalarFromBytes(pad)
	if err != nil {
		panic(fmt.Sprintf("invalid scalar constant %s: %v", s, err))
	}
	return out
}

// FieldZero returns the zero field element.
func FieldZero() FieldElement {
	return FieldElement{}
}

// FieldOne returns the field element 1 in Montgomery domain.
func FieldOne() FieldElement {
	var out FieldElement
	fiatfield.SetOne(&out.mont)
	return out
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
	if a.IsZero() {
		return FieldElement{}, errors.New("zero field element is not invertible")
	}
	return fieldInvAddchain(a), nil
}

// Precomputed small field constants in Montgomery domain.
var (
	fieldTwo   = FieldAdd(FieldOne(), FieldOne())
	fieldThree = FieldAdd(fieldTwo, FieldOne())
	fieldB     = FieldAdd(
		FieldAdd(
			FieldAdd(
				FieldAdd(
					FieldAdd(FieldOne(), FieldOne()),
					FieldOne(),
				),
				FieldOne(),
			),
			FieldOne(),
		),
		FieldAdd(FieldOne(), FieldOne()),
	)
)

func isZero32(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func reverse32To(dst *[32]uint8, src []byte) {
	for i := range 32 {
		dst[i] = src[31-i]
	}
}

func lt32LE(a, b [32]uint8) bool {
	return bytes.Compare(a[:], b[:]) < 0
}
