package secp256k1

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

type Point struct {
	X, Y *big.Int
	Inf  bool
}

var (
	P  = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	N  = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	Gx = mustHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	Gy = mustHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	B  = big.NewInt(7)
	G  = &Point{X: new(big.Int).Set(Gx), Y: new(big.Int).Set(Gy)}
)

func mustHex(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex constant")
	}
	return x
}

func Order() *big.Int {
	return new(big.Int).Set(N)
}

func FieldPrime() *big.Int {
	return new(big.Int).Set(P)
}

func NewInfinity() *Point {
	return &Point{Inf: true}
}

func Clone(p *Point) *Point {
	if p == nil || p.Inf {
		return NewInfinity()
	}
	return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}
}

func IsOnCurve(p *Point) bool {
	if p == nil {
		return false
	}
	if p.Inf {
		return true
	}
	if p.X.Sign() < 0 || p.X.Cmp(P) >= 0 || p.Y.Sign() < 0 || p.Y.Cmp(P) >= 0 {
		return false
	}
	lhs := mod(new(big.Int).Mul(p.Y, p.Y), P)
	x3 := mod(new(big.Int).Mul(p.X, p.X), P)
	x3.Mul(x3, p.X)
	x3.Add(x3, B)
	rhs := mod(x3, P)
	return lhs.Cmp(rhs) == 0
}

func Add(a, b *Point) *Point {
	if a == nil || a.Inf {
		return Clone(b)
	}
	if b == nil || b.Inf {
		return Clone(a)
	}
	if a.X.Cmp(b.X) == 0 {
		sumY := mod(new(big.Int).Add(a.Y, b.Y), P)
		if sumY.Sign() == 0 {
			return NewInfinity()
		}
		return Double(a)
	}
	lambdaNum := new(big.Int).Sub(b.Y, a.Y)
	lambdaDen := new(big.Int).Sub(b.X, a.X)
	lambda := divMod(lambdaNum, lambdaDen, P)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, a.X)
	x3.Sub(x3, b.X)
	x3 = mod(x3, P)

	y3 := new(big.Int).Sub(a.X, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, a.Y)
	y3 = mod(y3, P)
	return &Point{X: x3, Y: y3}
}

func Double(a *Point) *Point {
	if a == nil || a.Inf || a.Y.Sign() == 0 {
		return NewInfinity()
	}
	num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.X, a.X))
	den := new(big.Int).Mul(big.NewInt(2), a.Y)
	lambda := divMod(num, den, P)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), a.X))
	x3 = mod(x3, P)

	y3 := new(big.Int).Sub(a.X, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, a.Y)
	y3 = mod(y3, P)
	return &Point{X: x3, Y: y3}
}

func ScalarBaseMult(k *big.Int) *Point {
	return ScalarMult(G, k)
}

func ScalarMult(p *Point, k *big.Int) *Point {
	if k == nil || k.Sign() == 0 || p == nil || p.Inf {
		return NewInfinity()
	}
	n := mod(k, N)
	acc := NewInfinity()
	base := Clone(p)
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			acc = Add(acc, base)
		}
		base = Double(base)
	}
	return acc
}

func RandomScalar(reader io.Reader) (*big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	for {
		x, err := rand.Int(reader, N)
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

func ParseScalar(in []byte) (*big.Int, error) {
	if len(in) != 32 {
		return nil, errors.New("secp256k1 scalar must be 32 bytes")
	}
	x := new(big.Int).SetBytes(in)
	if x.Sign() == 0 || x.Cmp(N) >= 0 {
		return nil, errors.New("secp256k1 scalar out of range")
	}
	return x, nil
}

func ScalarBytes(x *big.Int) []byte {
	return bytesFixed(mod(x, N), 32)
}

func PointBytes(p *Point) ([]byte, error) {
	if p == nil || p.Inf || !IsOnCurve(p) {
		return nil, errors.New("invalid secp256k1 point")
	}
	out := make([]byte, 33)
	if p.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[1:], bytesFixed(p.X, 32))
	return out, nil
}

func PointFromBytes(in []byte) (*Point, error) {
	if len(in) != 33 || (in[0] != 0x02 && in[0] != 0x03) {
		return nil, errors.New("secp256k1 point must be compressed")
	}
	x := new(big.Int).SetBytes(in[1:])
	if x.Cmp(P) >= 0 {
		return nil, errors.New("point x out of field range")
	}
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	y2.Add(y2, B)
	y2 = mod(y2, P)

	exp := new(big.Int).Add(P, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, P)
	if mod(new(big.Int).Mul(y, y), P).Cmp(y2) != 0 {
		return nil, errors.New("point is not on curve")
	}
	wantOdd := in[0] == 0x03
	if (y.Bit(0) == 1) != wantOdd {
		y.Sub(P, y)
	}
	p := &Point{X: x, Y: y}
	if !IsOnCurve(p) {
		return nil, errors.New("point is not on curve")
	}
	return p, nil
}

func VerifyShare(commitments [][]byte, id uint32, share *big.Int) error {
	left := ScalarBaseMult(share)
	right, err := EvalCommitments(commitments, id)
	if err != nil {
		return err
	}
	if !Equal(left, right) {
		return errors.New("share does not match commitments")
	}
	return nil
}

func EvalCommitments(commitments [][]byte, id uint32) (*Point, error) {
	x := big.NewInt(int64(id))
	pow := big.NewInt(1)
	acc := NewInfinity()
	for _, enc := range commitments {
		c, err := PointFromBytes(enc)
		if err != nil {
			return nil, err
		}
		term := ScalarMult(c, pow)
		acc = Add(acc, term)
		pow.Mul(pow, x)
		pow.Mod(pow, N)
	}
	return acc, nil
}

func Equal(a, b *Point) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Inf || b.Inf {
		return a.Inf && b.Inf
	}
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

func SignECDSA(reader io.Reader, digest []byte, secret *big.Int, lowS bool) (r, s *big.Int, err error) {
	if len(digest) != 32 {
		return nil, nil, errors.New("ECDSA digest must be 32 bytes")
	}
	z := new(big.Int).SetBytes(digest)
	for {
		k, err := RandomScalar(reader)
		if err != nil {
			return nil, nil, err
		}
		rp := ScalarBaseMult(k)
		if rp.Inf {
			continue
		}
		r = mod(rp.X, N)
		if r.Sign() == 0 {
			continue
		}
		kinv := new(big.Int).ModInverse(k, N)
		if kinv == nil {
			continue
		}
		s = new(big.Int).Mul(r, secret)
		s.Add(s, z)
		s.Mul(s, kinv)
		s.Mod(s, N)
		if s.Sign() == 0 {
			continue
		}
		if lowS && s.Cmp(new(big.Int).Rsh(new(big.Int).Set(N), 1)) > 0 {
			s.Sub(N, s)
		}
		return r, s, nil
	}
}

func SignECDSAWithNonce(digest []byte, secret, nonce *big.Int, lowS bool) (r, s *big.Int, err error) {
	if len(digest) != 32 {
		return nil, nil, errors.New("ECDSA digest must be 32 bytes")
	}
	if secret == nil || secret.Sign() == 0 || nonce == nil || nonce.Sign() == 0 {
		return nil, nil, errors.New("secret and nonce must be non-zero")
	}
	z := new(big.Int).SetBytes(digest)
	k := mod(nonce, N)
	rp := ScalarBaseMult(k)
	if rp.Inf {
		return nil, nil, errors.New("nonce produced infinity")
	}
	r = mod(rp.X, N)
	if r.Sign() == 0 {
		return nil, nil, errors.New("nonce produced zero r")
	}
	kinv := new(big.Int).ModInverse(k, N)
	if kinv == nil {
		return nil, nil, errors.New("nonce is not invertible")
	}
	s = new(big.Int).Mul(r, secret)
	s.Add(s, z)
	s.Mul(s, kinv)
	s.Mod(s, N)
	if s.Sign() == 0 {
		return nil, nil, errors.New("zero s")
	}
	if lowS && s.Cmp(new(big.Int).Rsh(new(big.Int).Set(N), 1)) > 0 {
		s.Sub(N, s)
	}
	return r, s, nil
}

func VerifyECDSA(public *Point, digest []byte, r, s *big.Int) bool {
	if len(digest) != 32 || public == nil || public.Inf || !IsOnCurve(public) {
		return false
	}
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	z := new(big.Int).SetBytes(digest)
	w := new(big.Int).ModInverse(s, N)
	if w == nil {
		return false
	}
	u1 := mod(new(big.Int).Mul(z, w), N)
	u2 := mod(new(big.Int).Mul(r, w), N)
	p1 := ScalarBaseMult(u1)
	p2 := ScalarMult(public, u2)
	x := Add(p1, p2)
	if x.Inf {
		return false
	}
	v := mod(x.X, N)
	return v.Cmp(r) == 0
}

func AddPoints(points ...*Point) *Point {
	acc := NewInfinity()
	for _, p := range points {
		acc = Add(acc, p)
	}
	return acc
}

func mod(x, m *big.Int) *big.Int {
	out := new(big.Int).Mod(x, m)
	if out.Sign() < 0 {
		out.Add(out, m)
	}
	return out
}

func divMod(num, den, m *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(mod(den, m), m)
	if inv == nil {
		panic(fmt.Sprintf("non-invertible denominator %s", den))
	}
	out := new(big.Int).Mul(num, inv)
	return mod(out, m)
}

func bytesFixed(x *big.Int, size int) []byte {
	out := make([]byte, size)
	if x == nil {
		return out
	}
	b := x.Bytes()
	if len(b) > size {
		b = b[len(b)-size:]
	}
	copy(out[size-len(b):], b)
	return out
}
