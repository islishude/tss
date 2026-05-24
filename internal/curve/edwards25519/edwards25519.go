package edwards25519

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	fed "filippo.io/edwards25519"
)

var order *big.Int

func init() {
	order = new(big.Int)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
}

// Order returns a copy of the Ed25519 prime subgroup order.
func Order() *big.Int {
	return new(big.Int).Set(order)
}

// RandomScalar returns a non-zero scalar and its big.Int representation.
func RandomScalar(reader io.Reader) (*fed.Scalar, *big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	for {
		x, err := rand.Int(reader, order)
		if err != nil {
			return nil, nil, err
		}
		if x.Sign() == 0 {
			continue
		}
		s, err := ScalarFromBig(x)
		if err != nil {
			return nil, nil, err
		}
		return s, x, nil
	}
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

// PointFromBytes parses a point and rejects the identity.
func PointFromBytes(in []byte) (*fed.Point, error) {
	p, err := PointFromBytesAllowIdentity(in)
	if err != nil {
		return nil, err
	}
	if IsIdentity(p) {
		return nil, errors.New("identity point is not allowed")
	}
	return p, nil
}

// PointFromBytesAllowIdentity parses a point while allowing the identity.
func PointFromBytesAllowIdentity(in []byte) (*fed.Point, error) {
	if len(in) != 32 {
		return nil, errors.New("edwards25519 point must be 32 bytes")
	}
	p, err := fed.NewIdentityPoint().SetBytes(in)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// IsIdentity reports whether p is the group identity.
func IsIdentity(p *fed.Point) bool {
	return p != nil && p.Equal(fed.NewIdentityPoint()) == 1
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

// HashToScalar hashes length-delimited parts into a prime-order scalar.
func HashToScalar(parts ...[]byte) (*fed.Scalar, *big.Int) {
	h := sha512.New()
	for _, p := range parts {
		writeLen(h, len(p))
		h.Write(p)
	}
	sum := h.Sum(nil)
	s, _ := fed.NewScalar().SetUniformBytes(sum)
	return s, ScalarToBig(s)
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

func writeLen(w io.Writer, n int) {
	_, _ = w.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
