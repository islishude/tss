package secp256k1

import (
	"bytes"
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

// Precomputed modulus bytes in big-endian order (MSB at index 0) for canonical validation.
var (
	scalarModulus = [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	fieldModulus  = [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F}
)

// Precomputed small field constants in Montgomery domain.
// Derived as k * R mod P where R = 2^256:
//
//	fieldTwo   = Mont(2) = 0x00000000000000000000000000000000000000000000000000000002000007a2
//	fieldThree = Mont(3) = 0x0000000000000000000000000000000000000000000000000000000300000b73
//	fieldB     = Mont(7) = 0x0000000000000000000000000000000000000000000000000000000700001ab7
var (
	fieldTwo   = FieldElement{mont: fiatfield.MontgomeryDomainFieldElement{0x2000007a2, 0x0, 0x0, 0x0}}
	fieldThree = FieldElement{mont: fiatfield.MontgomeryDomainFieldElement{0x300000b73, 0x0, 0x0, 0x0}}
	fieldB     = FieldElement{mont: fiatfield.MontgomeryDomainFieldElement{0x700001ab7, 0x0, 0x0, 0x0}}
)

// halfOrder is N/2 as a precomputed Scalar for low-S checks.
// N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// The value is N/2 in Montgomery domain.
var halfOrder = Scalar{mont: fiatscalar.MontgomeryDomainFieldElement{0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0x7fffffffffffffff}}

// ScalarFromBytes parses a canonical 32-byte big-endian non-zero scalar.
func ScalarFromBytes(in []byte) (Scalar, error) {
	if len(in) != 32 {
		return Scalar{}, errors.New("secp256k1 scalar must be 32 bytes")
	}
	var be = [32]byte(in)
	if be == [32]byte{} {
		return Scalar{}, errors.New("secp256k1 scalar is zero")
	}
	if !lt32BE(be, scalarModulus) {
		return Scalar{}, errors.New("secp256k1 scalar out of range")
	}
	slices.Reverse(be[:]) // convert to little-endian for fiat-crypto
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromBytes((*[4]uint64)(&nonMont), &be)
	var out Scalar
	fiatscalar.ToMontgomery(&out.mont, &nonMont)
	return out, nil
}

// Bytes returns s as a fixed-width canonical big-endian scalar.
func (s Scalar) Bytes() []byte {
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromMontgomery(&nonMont, &s.mont)
	var raw [32]byte
	fiatscalar.ToBytes(&raw, (*[4]uint64)(&nonMont))
	slices.Reverse(raw[:])
	return raw[:]
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
	be := [32]byte(in)
	if !lt32BE(be, fieldModulus) {
		return FieldElement{}, errors.New("secp256k1 field element out of range")
	}
	slices.Reverse(be[:]) // convert to little-endian for fiat-crypto
	var nonMont fiatfield.NonMontgomeryDomainFieldElement
	fiatfield.FromBytes((*[4]uint64)(&nonMont), &be)
	var out FieldElement
	fiatfield.ToMontgomery(&out.mont, &nonMont)
	return out, nil
}

// Bytes returns f as a fixed-width canonical big-endian field element.
func (f FieldElement) Bytes() []byte {
	var nonMont fiatfield.NonMontgomeryDomainFieldElement
	fiatfield.FromMontgomery(&nonMont, &f.mont)
	var raw [32]byte
	fiatfield.ToBytes(&raw, (*[4]uint64)(&nonMont))
	slices.Reverse(raw[:]) // convert to big-endian for output
	return raw[:]
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

// FieldSelect returns a if bit is 0, b if bit is 1 (constant-time).
// It uses a bitwise mask so there is no branch on bit.
func FieldSelect(bit uint64, a, b FieldElement) FieldElement {
	mask := -bit // 0xFFFF... if bit==1, 0 if bit==0
	var out FieldElement
	out.mont[0] = (mask & b.mont[0]) | (^mask & a.mont[0])
	out.mont[1] = (mask & b.mont[1]) | (^mask & a.mont[1])
	out.mont[2] = (mask & b.mont[2]) | (^mask & a.mont[2])
	out.mont[3] = (mask & b.mont[3]) | (^mask & a.mont[3])
	return out
}

// nonzeroTo01 returns 0 if x==0, 1 if x!=0 (constant-time).
// For any non-zero uint64 x, (x | -x) has the MSB set.
func nonzeroTo01(x uint64) uint64 {
	return (x | (^x + 1)) >> 63
}

// fieldIsZero returns 1 if f is the zero field element, 0 otherwise (constant-time).
// It uses fiatfield.Nonzero as the primitive and converts the result to 0/1.
func fieldIsZero(f FieldElement) uint64 {
	var nz uint64
	fiatfield.Nonzero(&nz, (*[4]uint64)(&f.mont))
	return nonzeroTo01(nz) ^ 1 // invert: 1 if zero, 0 if non-zero
}

// fieldEq returns 1 if a and b are the same field element, 0 otherwise (constant-time).
func fieldEq(a, b FieldElement) uint64 {
	or := (a.mont[0] ^ b.mont[0]) |
		(a.mont[1] ^ b.mont[1]) |
		(a.mont[2] ^ b.mont[2]) |
		(a.mont[3] ^ b.mont[3])
	return nonzeroTo01(or) ^ 1 // invert: 1 if equal (or==0), 0 otherwise
}

func lt32BE(a, b [32]byte) bool {
	return bytes.Compare(a[:], b[:]) < 0
}

// sub32BE performs a 256-bit subtraction a = a - b in-place.
// It assumes a >= b. The result is a - b (no modular wrap).
func sub32BE(a *[32]byte, b [32]byte) {
	var borrow uint16
	for i := 31; i >= 0; i-- {
		diff := uint16(a[i]) - uint16(b[i]) - borrow
		// borrow is 1 if diff underflowed past 0xFF, otherwise 0.
		if diff > 0xFF {
			borrow = 1
		} else {
			borrow = 0
		}
		a[i] = byte(diff)
	}
}

// scalarLessOrEqual returns true if a <= b as unsigned 256-bit integers.
// Both a and b must be reduced scalars in [0, n). The comparison converts
// from Montgomery to non-Montgomery form and compares the integer limbs
// without allocating or going through byte reversal.
func scalarLessOrEqual(a, b Scalar) bool {
	var aNonMont, bNonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromMontgomery(&aNonMont, &a.mont)
	fiatscalar.FromMontgomery(&bNonMont, &b.mont)
	// Compare limbs from most significant to least significant (big-endian order).
	for i := 3; i >= 0; i-- {
		if aNonMont[i] != bNonMont[i] {
			return aNonMont[i] < bNonMont[i]
		}
	}
	return true // equal
}
