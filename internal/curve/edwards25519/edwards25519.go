package edwards25519

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"slices"

	fed "filippo.io/edwards25519"
)

var (
	// cofactorScalar is the Ed25519 cofactor (8) as a little-endian scalar, used to
	// detect small-order points during deserialization.
	cofactorScalar    = fed.NewScalar()
	invCofactorScalar = fed.NewScalar()

	scalarOne = fed.NewScalar()
)

func init() {
	cofactorBytes := [32]byte{8}
	if _, err := cofactorScalar.SetCanonicalBytes(cofactorBytes[:]); err != nil {
		panic("edwards25519: failed to initialize cofactor scalar: " + err.Error())
	}
	invCofactorScalar = invCofactorScalar.Invert(cofactorScalar)

	oneBytes := [32]byte{1}
	if _, err := scalarOne.SetCanonicalBytes(oneBytes[:]); err != nil {
		panic("edwards25519: failed to initialize scalar one: " + err.Error())
	}
}

// orderBytes is the precomputed prime subgroup order
var orderBytes = [32]byte{
	0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x14, 0xde, 0xf9, 0xde,
	0xa2, 0xf7, 0x9c, 0xd6,
	0x58, 0x12, 0x63, 0x1a,
	0x5c, 0xf5, 0xd3, 0xed,
}

// Order returns a copy of the Ed25519 prime subgroup order.
func Order() *big.Int {
	return new(big.Int).SetBytes(orderBytes[:])
}

// ScalarZero returns the scalar value 0 as a new mutable scalar.
func ScalarZero() *fed.Scalar {
	return fed.NewScalar()
}

// ScalarOne returns the scalar value 1 as a new mutable scalar.
func ScalarOne() *fed.Scalar {
	return fed.NewScalar().Set(scalarOne)
}

// RandomScalar returns a uniformly random non-zero scalar using rejection sampling.
// The reader is consumed in big-endian order to preserve deterministic test vectors
// that rely on a fixed pseudorandom stream.
func RandomScalar(reader io.Reader) (*fed.Scalar, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var be [32]byte
	var le [32]byte
	for {
		if _, err := io.ReadFull(reader, be[:]); err != nil {
			return nil, err
		}
		// Clear the top 3 bits of the most-significant BE byte so the candidate
		// is < 2^253 ≪ order, avoiding most rejections.
		be[0] &= 0x1f
		// Reject zero.
		var allZero byte
		for _, b := range be {
			allZero |= b
		}
		if allZero == 0 {
			continue
		}
		// Convert to little-endian for SetCanonicalBytes.
		for i := range be {
			le[i] = be[len(be)-1-i]
		}
		s, err := fed.NewScalar().SetCanonicalBytes(le[:])
		if err != nil {
			continue
		}
		return s, nil
	}
}

// ScalarFromBig reduces x modulo the subgroup order and returns a scalar.
func ScalarFromBig(x *big.Int) (*fed.Scalar, error) {
	if x == nil {
		return nil, errors.New("nil scalar")
	}
	n := new(big.Int).Mod(x, Order())
	if n.Sign() < 0 {
		n.Add(n, Order())
	}
	le := n.FillBytes(make([]byte, 32))
	slices.Reverse(le)
	return fed.NewScalar().SetCanonicalBytes(le[:])
}

// ScalarFromUint64 returns x as a scalar. x must be less than 2^64, which is
// far below the Ed25519 subgroup order.
func ScalarFromUint64(x uint64) *fed.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], x)
	s, _ := fed.NewScalar().SetCanonicalBytes(b[:])
	return s
}

// ScalarToBig converts a scalar to a big.Int using little-endian scalar bytes.
func ScalarToBig(s *fed.Scalar) *big.Int {
	if s == nil {
		return new(big.Int)
	}
	le := s.Bytes()
	slices.Reverse(le)
	return new(big.Int).SetBytes(le)
}

// ScalarFromCanonical parses a canonical 32-byte Ed25519 scalar.
func ScalarFromCanonical(in []byte) (*fed.Scalar, error) {
	// It checks the length internally and rejects scalars that are not canonical,
	// so we don't need to check those conditions here.
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
		pow.Mod(pow, Order())
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
func VerifyScalarShare(commitments [][]byte, id uint32, share *fed.Scalar) error {
	if share == nil {
		return errors.New("nil scalar share")
	}
	left := fed.NewIdentityPoint().ScalarBaseMult(share)
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
		_, _ = h.Write(p)
	}
	// No error can occur since the input is always 64 bytes, so we ignore it.
	s, _ := fed.NewScalar().SetUniformBytes(h.Sum(nil))
	return s, ScalarToBig(s)
}

// Ed25519Challenge computes the RFC 8032 challenge H(R || A || msg).
func Ed25519Challenge(R, A, msg []byte) (*fed.Scalar, *big.Int) {
	h := sha512.New()
	_, _ = h.Write(R)
	_, _ = h.Write(A)
	_, _ = h.Write(msg)

	// No error can occur since the input is always 64 bytes, so we ignore it.
	s, _ := fed.NewScalar().SetUniformBytes(h.Sum(nil))
	return s, ScalarToBig(s)
}
