package secp256k1

import (
	"fmt"
	"math/big"
)

// Point is an affine secp256k1 point backed by fiat-crypto field elements.
type Point struct {
	X, Y FieldElement
	Inf  bool
}

// G is the SEC 2 base point.
var G = &Point{
	X: fieldElementFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
	Y: fieldElementFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
}

func fieldElementFromHex(s string) FieldElement {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex constant")
	}
	b := x.Bytes()
	pad := make([]byte, 32)
	copy(pad[32-len(b):], b)
	f, err := FieldElementFromBytes(pad)
	if err != nil {
		panic(fmt.Sprintf("invalid field element constant: %v", err))
	}
	return f
}

// NewInfinity returns the point at infinity.
func NewInfinity() *Point {
	return &Point{Inf: true}
}

// Clone returns a deep copy of p.
func Clone(p *Point) *Point {
	if p == nil || p.Inf {
		return NewInfinity()
	}
	return &Point{X: p.X, Y: p.Y}
}

// IsOnCurve reports whether p satisfies the secp256k1 curve equation.
func IsOnCurve(p *Point) bool {
	if p == nil {
		return false
	}
	if p.Inf {
		return true
	}
	y2 := FieldSquare(p.Y)
	x3 := FieldAdd(FieldMul(FieldSquare(p.X), p.X), fieldB)
	return y2.Equal(x3)
}

// Add returns the elliptic-curve group sum of a and b.
func Add(a, b *Point) *Point {
	if a == nil || a.Inf {
		return Clone(b)
	}
	if b == nil || b.Inf {
		return Clone(a)
	}
	if a.X.Equal(b.X) {
		sumY := FieldAdd(a.Y, b.Y)
		if sumY.IsZero() {
			return NewInfinity()
		}
		return Double(a)
	}
	lambdaNum := FieldSub(b.Y, a.Y)
	lambdaDen := FieldSub(b.X, a.X)
	lambdaInv, err := FieldInvert(lambdaDen)
	if err != nil {
		panic(fmt.Sprintf("non-invertible denominator in Add: %x", lambdaDen.Bytes()))
	}
	lambda := FieldMul(lambdaNum, lambdaInv)

	x3 := FieldSub(FieldSub(FieldSquare(lambda), a.X), b.X)
	y3 := FieldSub(FieldMul(lambda, FieldSub(a.X, x3)), a.Y)
	return &Point{X: x3, Y: y3}
}

// Double returns 2*a in the secp256k1 group.
func Double(a *Point) *Point {
	if a == nil || a.Inf || a.Y.IsZero() {
		return NewInfinity()
	}
	num := FieldMul(fieldThree, FieldSquare(a.X))
	den := FieldMul(fieldTwo, a.Y)
	lambdaInv, err := FieldInvert(den)
	if err != nil {
		panic(fmt.Sprintf("non-invertible denominator in Double: %x", den.Bytes()))
	}
	lambda := FieldMul(num, lambdaInv)

	x3 := FieldSub(FieldSquare(lambda), FieldMul(fieldTwo, a.X))
	y3 := FieldSub(FieldMul(lambda, FieldSub(a.X, x3)), a.Y)
	return &Point{X: x3, Y: y3}
}

// Equal reports whether a and b encode the same curve point.
func Equal(a, b *Point) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Inf || b.Inf {
		return a.Inf && b.Inf
	}
	return a.X.Equal(b.X) && a.Y.Equal(b.Y)
}

// AddPoints returns the sum of all non-nil points.
func AddPoints(points ...*Point) *Point {
	acc := NewInfinity()
	for _, p := range points {
		acc = Add(acc, p)
	}
	return acc
}
