package edwards25519

import (
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	fed "filippo.io/edwards25519"
)

var order *big.Int
var orderBE [32]byte

// cofactorScalar is the Ed25519 cofactor (8) as a little-endian scalar, used to
// detect small-order points during deserialization.
var cofactorScalar *fed.Scalar
var invCofactorScalar *fed.Scalar

func init() {
	order = new(big.Int)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	order.FillBytes(orderBE[:])

	cofactorScalar = fed.NewScalar()
	cofactorBytes := [32]byte{8}
	if _, err := cofactorScalar.SetCanonicalBytes(cofactorBytes[:]); err != nil {
		panic("edwards25519: failed to initialize cofactor scalar: " + err.Error())
	}
	invCofactorScalar = fed.NewScalar().Invert(cofactorScalar)
}

// Order returns a copy of the Ed25519 prime subgroup order.
func Order() *big.Int {
	return new(big.Int).Set(order)
}

// RandomScalar returns a non-zero scalar and its big.Int representation.
func RandomScalar(reader io.Reader) (*fed.Scalar, *big.Int, error) {
	x, err := FiatRandomScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	s, err := x.ToFed()
	if err != nil {
		return nil, nil, err
	}
	return s, x.Big(), nil
}

// ScalarFromBig reduces x modulo the subgroup order and returns a scalar.
func ScalarFromBig(x *big.Int) (*fed.Scalar, error) {
	if x == nil {
		return nil, errors.New("nil scalar")
	}
	return fed.NewScalar().SetCanonicalBytes(FiatScalarFromBig(x).Bytes())
}

// ScalarToBig converts a scalar to a big.Int using little-endian scalar bytes.
func ScalarToBig(s *fed.Scalar) *big.Int {
	if s == nil {
		return new(big.Int)
	}
	return littleToBig(s.Bytes())
}

// ScalarFromCanonical parses a canonical 32-byte Ed25519 scalar.
func ScalarFromCanonical(in []byte) (*fed.Scalar, error) {
	if len(in) != 32 {
		return nil, errors.New("edwards25519 scalar must be 32 bytes")
	}
	return fed.NewScalar().SetCanonicalBytes(in)
}

// ScalarBaseMultBig returns x times the Ed25519 base point.
func ScalarBaseMultBig(x *big.Int) (*fed.Point, error) {
	s, err := ScalarFromBig(x)
	if err != nil {
		return nil, err
	}
	return fed.NewIdentityPoint().ScalarBaseMult(s), nil
}

// ScalarBaseMult returns x times the Ed25519 base point.
func ScalarBaseMult(x Scalar) (*fed.Point, error) {
	s, err := x.ToFed()
	if err != nil {
		return nil, err
	}
	return fed.NewIdentityPoint().ScalarBaseMult(s), nil
}

// ScalarMult returns x times p.
func ScalarMult(x Scalar, p *fed.Point) (*fed.Point, error) {
	if p == nil {
		return nil, errors.New("nil point")
	}
	s, err := x.ToFed()
	if err != nil {
		return nil, err
	}
	return fed.NewIdentityPoint().ScalarMult(s, p), nil
}

// PointFromBytes parses a native compressed 32-byte point and rejects the
// identity as well as points that are not in the prime-order subgroup.
// Non-prime-order points (including the eight small-order points) are rejected.
func PointFromBytes(in []byte) (*fed.Point, error) {
	p, err := PointFromBytesAllowIdentity(in)
	if err != nil {
		return nil, err
	}
	if IsIdentity(p) {
		return nil, errors.New("identity point is not allowed")
	}
	// Small-order points are already rejected by PointFromBytesAllowIdentity.
	return p, nil
}

// PointFromBytesAllowIdentity parses a native compressed 32-byte point and
// rejects points that are not in the prime-order subgroup. The identity
// point is allowed.
func PointFromBytesAllowIdentity(in []byte) (*fed.Point, error) {
	if len(in) != 32 {
		return nil, errors.New("edwards25519 point must be 32 bytes")
	}
	p, err := fed.NewIdentityPoint().SetBytes(in)
	if err != nil {
		return nil, err
	}
	if !IsIdentity(p) && !isPrimeOrderPoint(p) {
		return nil, errors.New("point is not in the prime-order subgroup")
	}
	return p, nil
}

// IsIdentity reports whether p is the group identity.
func IsIdentity(p *fed.Point) bool {
	if p == nil {
		return false
	}
	return p.Equal(fed.NewIdentityPoint()) == 1
}

// isSmallOrderPoint reports whether [8]P == identity. Callers that distinguish
// identity from small-order points must check IsIdentity(p) first.
func isSmallOrderPoint(p *fed.Point) bool {
	if p == nil {
		return false
	}
	check := fed.NewIdentityPoint().ScalarMult(cofactorScalar, p)
	return check.Equal(fed.NewIdentityPoint()) == 1
}

// isPrimeOrderPoint reports whether p has no torsion component. Multiplying by
// the cofactor maps any point to the prime-order subgroup; multiplying back by
// 1/8 should recover exactly p only when p was already in that subgroup.
func isPrimeOrderPoint(p *fed.Point) bool {
	if p == nil {
		return false
	}
	if isSmallOrderPoint(p) {
		return IsIdentity(p)
	}
	cofactored := fed.NewIdentityPoint().MultByCofactor(p)
	projected := fed.NewIdentityPoint().ScalarMult(invCofactorScalar, cofactored)
	return projected.Equal(p) == 1
}

// AddPoints returns the sum of all non-nil Edwards points.
func AddPoints(points ...*fed.Point) *fed.Point {
	acc := fed.NewIdentityPoint()
	for _, p := range points {
		if p == nil {
			continue
		}
		acc.Add(acc, p)
	}
	return acc
}

// EvalCommitments evaluates public polynomial commitments at participant id.
func EvalCommitments(commitments [][]byte, id uint32) ([]byte, error) {
	x := big.NewInt(int64(id))
	pow := big.NewInt(1)
	acc := fed.NewIdentityPoint()
	for _, enc := range commitments {
		c, err := PointFromBytesAllowIdentity(enc)
		if err != nil {
			return nil, err
		}
		sc, err := ScalarFromBig(pow)
		if err != nil {
			return nil, err
		}
		term := fed.NewIdentityPoint().ScalarMult(sc, c)
		acc.Add(acc, term)
		pow.Mul(pow, x)
		pow.Mod(pow, order)
	}
	return acc.Bytes(), nil
}

// VerifyShare checks a private Shamir share against public commitments.
func VerifyShare(commitments [][]byte, id uint32, share *big.Int) error {
	left, err := ScalarBaseMultBig(share)
	if err != nil {
		return err
	}
	rightBytes, err := EvalCommitments(commitments, id)
	if err != nil {
		return err
	}
	right, err := PointFromBytesAllowIdentity(rightBytes)
	if err != nil {
		return err
	}
	if left.Equal(right) != 1 {
		return errors.New("share does not match commitments")
	}
	return nil
}

// VerifyScalarShare checks a private Shamir share against public commitments.
func VerifyScalarShare(commitments [][]byte, id uint32, share Scalar) error {
	left, err := ScalarBaseMult(share)
	if err != nil {
		return err
	}
	rightBytes, err := EvalCommitments(commitments, id)
	if err != nil {
		return err
	}
	right, err := PointFromBytesAllowIdentity(rightBytes)
	if err != nil {
		return err
	}
	if left.Equal(right) != 1 {
		return errors.New("share does not match commitments")
	}
	return nil
}

// HashToScalar hashes parts into a prime-order scalar via direct concatenation
// without length-delimited encoding, per RFC 9591 Section 3.1.
func HashToScalar(parts ...[]byte) (*fed.Scalar, *big.Int) {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	sum := h.Sum(nil)
	s, _ := fed.NewScalar().SetUniformBytes(sum)
	return s, ScalarToBig(s)
}

// HashToFiatScalar hashes parts into a prime-order scalar in fiat form.
func HashToFiatScalar(parts ...[]byte) Scalar {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	sum := h.Sum(nil)
	s, _ := fed.NewScalar().SetUniformBytes(sum)
	return FiatScalarFromFed(s)
}

// Ed25519Challenge computes the RFC 8032 challenge H(R || A || msg).
func Ed25519Challenge(R, A, msg []byte) (*fed.Scalar, *big.Int) {
	h := sha512.New()
	h.Write(R)
	h.Write(A)
	h.Write(msg)
	sum := h.Sum(nil)
	s, _ := fed.NewScalar().SetUniformBytes(sum)
	return s, ScalarToBig(s)
}

// Ed25519ChallengeFiat computes the RFC 8032 challenge H(R || A || msg).
func Ed25519ChallengeFiat(R, A, msg []byte) Scalar {
	h := sha512.New()
	h.Write(R)
	h.Write(A)
	h.Write(msg)
	sum := h.Sum(nil)
	s, _ := fed.NewScalar().SetUniformBytes(sum)
	return FiatScalarFromFed(s)
}

func bigToLittle(x *big.Int, size int) []byte {
	out := make([]byte, size)
	b := x.Bytes()
	for i := 0; i < len(b) && i < size; i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func littleToBig(in []byte) *big.Int {
	be := make([]byte, len(in))
	for i := range in {
		be[len(in)-1-i] = in[i]
	}
	return new(big.Int).SetBytes(be)
}
