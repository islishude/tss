package secp256k1

import (
	"fmt"
	"math/big"

	fiatscalar "github.com/islishude/tss/internal/fiat/secp256k1scalar"
)

// ScalarFromBigInt converts a *big.Int to Scalar, reducing mod N.
func ScalarFromBigInt(x *big.Int) Scalar {
	return scalarFromBig(x)
}

// ScalarFromUint64 converts v to a Scalar without using big.Int.
// Values used by protocol code are party identifiers, so v must be non-zero.
// Zero is represented as ScalarZero for internal polynomial evaluation at x=0.
func ScalarFromUint64(v uint64) Scalar {
	return scalarFromUint64(v)
}

// ScalarFromBytesModOrder reduces a 32-byte big-endian integer modulo the
// secp256k1 subgroup order. The zero result is accepted.
//
// Since every 256-bit input is less than 2*n, reduction requires at most one
// subtraction of the subgroup order.
func ScalarFromBytesModOrder(in []byte) (Scalar, error) {
	if len(in) != ScalarSize {
		return Scalar{}, fmt.Errorf("secp256k1 scalar input must be %d bytes", ScalarSize)
	}
	var be [ScalarSize]byte
	copy(be[:], in)
	if !lt32BE(be, scalarModulus) {
		sub32BE(&be, scalarModulus)
	}
	return mustScalarFromBytes(be), nil
}

// ScalarFromFieldElement reduces a base-field element modulo the subgroup order.
func ScalarFromFieldElement(x FieldElement) Scalar {
	return scalarFromFieldElement(x)
}

func scalarFromBig(x *big.Int) Scalar {
	order := Order()
	reduced := new(big.Int).Mod(x, order)
	if reduced.Sign() < 0 {
		reduced.Add(reduced, order)
	}
	pad := reduced.FillBytes(make([]byte, 32))
	s, err := ScalarFromBytes(pad)
	if err != nil {
		return ScalarZero()
	}
	return s
}

// FieldElementFromBigInt converts a *big.Int to FieldElement, reducing mod P.
func FieldElementFromBigInt(x *big.Int) FieldElement {
	modulus := new(big.Int).SetBytes(fieldModulus[:])
	reduced := new(big.Int).Mod(x, modulus)
	if reduced.Sign() < 0 {
		reduced.Add(reduced, modulus)
	}
	pad := reduced.FillBytes(make([]byte, 32))
	f, _ := FieldElementFromBytes(pad)
	return f
}

// scalarFromFieldElement converts a field element X-coordinate to a Scalar
// by reducing it modulo the group order n. For secp256k1, p - n < n, so at most
// one subtraction of n is needed — no big.Int required.
func scalarFromFieldElement(x FieldElement) Scalar {
	b := x.Bytes() // 32-byte big-endian, non-Montgomery
	var be [32]byte
	copy(be[:], b)
	if !lt32BE(be, scalarModulus) {
		// X >= n, reduce by subtracting n once (p - n < n guarantees one subtraction suffices).
		sub32BE(&be, scalarModulus)
	}
	return mustScalarFromBytes(be)
}

// mustScalarFromBytes parses a 32-byte big-endian value as a Scalar,
// returning ScalarZero() if the value cannot be represented (e.g. zero).
func mustScalarFromBytes(be [32]byte) Scalar {
	s, err := ScalarFromBytes(be[:])
	if err != nil {
		return ScalarZero()
	}
	return s
}

func scalarFromUint64(v uint64) Scalar {
	var le [32]uint8
	le[0] = uint8(v)
	le[1] = uint8(v >> 8)
	le[2] = uint8(v >> 16)
	le[3] = uint8(v >> 24)
	le[4] = uint8(v >> 32)
	le[5] = uint8(v >> 40)
	le[6] = uint8(v >> 48)
	le[7] = uint8(v >> 56)
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromBytes((*[4]uint64)(&nonMont), &le)
	var out Scalar
	fiatscalar.ToMontgomery(&out.mont, &nonMont)
	return out
}
