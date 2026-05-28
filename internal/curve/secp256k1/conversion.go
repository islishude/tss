package secp256k1

import (
	"math/big"

	fiatscalar "github.com/islishude/tss/internal/fiat/secp256k1scalar"
)

// ScalarFromBigInt converts a *big.Int to Scalar, reducing mod N.
func ScalarFromBigInt(x *big.Int) Scalar {
	return scalarFromBig(x)
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
	modulus := new(big.Int).SetBytes(reverseBytes(fieldModulusLE[:]))
	reduced := new(big.Int).Mod(x, modulus)
	if reduced.Sign() < 0 {
		reduced.Add(reduced, modulus)
	}
	pad := reduced.FillBytes(make([]byte, 32))
	f, _ := FieldElementFromBytes(pad)
	return f
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

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range len(b) {
		out[i] = b[len(b)-1-i]
	}
	return out
}
