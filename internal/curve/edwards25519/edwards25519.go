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

func Order() *big.Int {
	return new(big.Int).Set(order)
}

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

func ScalarFromBig(x *big.Int) (*fed.Scalar, error) {
	if x == nil {
		return nil, errors.New("nil scalar")
	}
	n := new(big.Int).Mod(new(big.Int).Set(x), order)
	if n.Sign() < 0 {
		n.Add(n, order)
	}
	buf := bigToLittle(n, 32)
	return fed.NewScalar().SetCanonicalBytes(buf)
}

func ScalarToBig(s *fed.Scalar) *big.Int {
	if s == nil {
		return new(big.Int)
	}
	return littleToBig(s.Bytes())
}

func ScalarFromCanonical(in []byte) (*fed.Scalar, error) {
	if len(in) != 32 {
		return nil, errors.New("edwards25519 scalar must be 32 bytes")
	}
	return fed.NewScalar().SetCanonicalBytes(in)
}

func ScalarBaseMultBig(x *big.Int) (*fed.Point, error) {
	s, err := ScalarFromBig(x)
	if err != nil {
		return nil, err
	}
	return fed.NewIdentityPoint().ScalarBaseMult(s), nil
}

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

func IsIdentity(p *fed.Point) bool {
	return p != nil && p.Equal(fed.NewIdentityPoint()) == 1
}

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
