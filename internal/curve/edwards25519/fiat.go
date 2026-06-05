package edwards25519

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	fed "filippo.io/edwards25519"
	fiatscalar "github.com/islishude/tss/internal/fiat/ed25519scalar"
)

// Scalar is an Ed25519 subgroup scalar backed by fiat-crypto arithmetic.
type Scalar struct {
	mont fiatscalar.MontgomeryDomainFieldElement
}

// ScalarFromCanonicalFiat parses a canonical Ed25519 scalar into fiat form.
// Zero is accepted because canonical scalar encodings are in [0, order).
func ScalarFromCanonicalFiat(in []byte) (Scalar, error) {
	if len(in) != 32 {
		return Scalar{}, errors.New("edwards25519 scalar must be 32 bytes")
	}
	x := littleToBig(in)
	if x.Cmp(order) >= 0 {
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

// FiatScalarFromUint64 returns x reduced modulo the Ed25519 subgroup order.
func FiatScalarFromUint64(x uint64) Scalar {
	var raw [32]uint8
	for i := range 8 {
		raw[i] = uint8(x >> (8 * i))
	}
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
	return raw[:]
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

// ScalarInv returns a^-1 modulo the Ed25519 subgroup order.
func ScalarInv(a Scalar) (Scalar, error) {
	if a.IsZero() {
		return Scalar{}, errors.New("zero scalar has no inverse")
	}
	fedA, err := a.ToFed()
	if err != nil {
		return Scalar{}, err
	}
	return FiatScalarFromFed(fed.NewScalar().Invert(fedA)), nil
}

// ScalarZero returns the zero scalar.
func ScalarZero() Scalar { return Scalar{} }

// ScalarOne returns the scalar 1.
func ScalarOne() Scalar {
	var out Scalar
	fiatscalar.SetOne(&out.mont)
	return out
}

// ScalarEqual reports whether a and b represent the same field element.
func ScalarEqual(a, b Scalar) bool {
	return a.mont == b.mont
}

// FiatScalarFromFed converts a filippo.io/edwards25519 scalar into a fiat scalar
// without an intermediate big.Int allocation.
func FiatScalarFromFed(s *fed.Scalar) Scalar {
	b := s.Bytes() // canonical 32-byte LE, already < order
	var nonMont fiatscalar.NonMontgomeryDomainFieldElement
	fiatscalar.FromBytes((*[4]uint64)(&nonMont), (*[32]byte)(b))
	var out Scalar
	fiatscalar.ToMontgomery(&out.mont, &nonMont)
	return out
}

// ToFed converts the fiat scalar to a filippo.io/edwards25519 scalar
// without an intermediate allocation.
func (s Scalar) ToFed() (*fed.Scalar, error) {
	return fed.NewScalar().SetCanonicalBytes(s.Bytes())
}

// FiatRandomScalar returns a random non-zero fiat scalar.
func FiatRandomScalar(reader io.Reader) (Scalar, error) {
	if reader == nil {
		reader = rand.Reader
	}
	for {
		var candidate [32]byte
		if _, err := io.ReadFull(reader, candidate[:]); err != nil {
			return Scalar{}, err
		}
		candidate[0] &= 0x1f
		if isZeroBE(candidate[:]) || !lessThanOrderBE(candidate[:]) {
			continue
		}
		var le [32]byte
		for i := range candidate {
			le[i] = candidate[len(candidate)-1-i]
		}
		return ScalarFromCanonicalFiat(le[:])
	}
}

func isZeroBE(in []byte) bool {
	var acc byte
	for _, b := range in {
		acc |= b
	}
	return acc == 0
}

func lessThanOrderBE(in []byte) bool {
	for i, b := range in {
		if b < orderBE[i] {
			return true
		}
		if b > orderBE[i] {
			return false
		}
	}
	return false
}
