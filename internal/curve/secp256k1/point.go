package secp256k1

import (
	fiatfield "github.com/islishude/tss/internal/fiat/secp256k1field"
)

// Point is an affine secp256k1 point backed by fiat-crypto field elements.
type Point struct {
	X, Y FieldElement
	Inf  uint64 // 0 = finite point, 1 = point at infinity
}

// G is the SEC 2 base point (generator) for secp256k1.
// Coordinates are precomputed in Montgomery domain.
var G = &Point{
	X: FieldElement{mont: fiatfield.MontgomeryDomainFieldElement{0xd7362e5a487e2097, 0x231e295329bc66db, 0x979f48c033fd129c, 0x9981e643e9089f48}},
	Y: FieldElement{mont: fiatfield.MontgomeryDomainFieldElement{0xb15ea6d2d3dbabe2, 0x8dfc5d5d1f1dc64d, 0x70b6b59aac19c136, 0xcf3f851fd4a582d6}},
}

// NewInfinity returns the point at infinity.
func NewInfinity() *Point {
	return &Point{Inf: 1}
}

// Clone returns a deep copy of p.
func Clone(p *Point) *Point {
	if p == nil || p.Inf != 0 {
		return NewInfinity()
	}
	return &Point{X: p.X, Y: p.Y}
}

// IsOnCurve reports whether p satisfies the secp256k1 curve equation.
func IsOnCurve(p *Point) bool {
	if p == nil {
		return false
	}
	if p.Inf != 0 {
		return true
	}
	y2 := FieldSquare(p.Y)
	x3 := FieldAdd(FieldMul(FieldSquare(p.X), p.X), fieldB)
	return y2.Equal(x3)
}

// PointSelect returns a if bit is 0, b if bit is 1 (constant-time).
func PointSelect(bit uint64, a, b *Point) *Point {
	mask := -bit // all-ones if bit==1, 0 if bit==0
	return &Point{
		X:   FieldSelect(bit, a.X, b.X),
		Y:   FieldSelect(bit, a.Y, b.Y),
		Inf: (mask & b.Inf) | (^mask & a.Inf),
	}
}

// u64Select returns a if bit is 0, b if bit is 1 (constant-time).
func u64Select(bit, a, b uint64) uint64 {
	mask := -bit
	return (mask & b) | (^mask & a)
}

// Add returns the elliptic-curve group sum of a and b.
// All branches on point values are replaced with constant-time selects;
// the only early exit is for nil inputs, which is a caller error.
func Add(a, b *Point) *Point {
	if a == nil || b == nil {
		panic("secp256k1: Add called with nil point")
	}

	// Always compute the regular affine addition formula.
	// When a.X == b.X the denominator is zero, fieldInvAddchain returns zero,
	// and the result is discarded by the select chain below.
	lambdaNum := FieldSub(b.Y, a.Y)
	lambdaDen := FieldSub(b.X, a.X)
	lambda := FieldMul(lambdaNum, fieldInvAddchain(lambdaDen))
	regX := FieldSub(FieldSub(FieldSquare(lambda), a.X), b.X)
	regY := FieldSub(FieldMul(lambda, FieldSub(a.X, regX)), a.Y)

	// Delegate to Double for the tangent-case fallback.
	dbl := Double(a)
	dblX, dblY, dblInf := dbl.X, dbl.Y, dbl.Inf

	// Determine which case applies (all constant-time bit operations).
	aInf := a.Inf
	bInf := b.Inf
	xEq := fieldEq(a.X, b.X)
	ySumZero := fieldIsZero(FieldAdd(a.Y, b.Y))
	samePoint := xEq & ^ySumZero // a == b (and not inverse)
	invPoints := xEq & ySumZero  // a == -b

	// Start with the regular addition result and override by priority
	// (lowest to highest).
	resultX := regX
	resultY := regY
	resultInf := uint64(0)

	// Case: same point → use Double(a).
	resultX = FieldSelect(samePoint, resultX, dblX)
	resultY = FieldSelect(samePoint, resultY, dblY)
	resultInf = u64Select(samePoint, resultInf, dblInf)

	// Case: inverse points → infinity.
	resultX = FieldSelect(invPoints, resultX, FieldZero())
	resultY = FieldSelect(invPoints, resultY, FieldZero())
	resultInf = u64Select(invPoints, resultInf, 1)

	// Case: b is infinity (and a is not) → result = a.
	condBInf := bInf & ^aInf
	resultX = FieldSelect(condBInf, resultX, a.X)
	resultY = FieldSelect(condBInf, resultY, a.Y)
	resultInf = u64Select(condBInf, resultInf, a.Inf)

	// Case: a is infinity → result = b (highest priority).
	resultX = FieldSelect(aInf, resultX, b.X)
	resultY = FieldSelect(aInf, resultY, b.Y)
	resultInf = u64Select(aInf, resultInf, b.Inf)

	return &Point{X: resultX, Y: resultY, Inf: resultInf}
}

// Double returns 2*a in the secp256k1 group.
// It unconditionally evaluates the doubling formula; the result is selected
// based on a constant-time infinity / zero-y check.
func Double(a *Point) *Point {
	if a == nil {
		panic("secp256k1: Double called with nil point")
	}

	num := FieldMul(fieldThree, FieldSquare(a.X))
	den := FieldMul(fieldTwo, a.Y)
	// fieldInvAddchain is safe on zero input — it returns zero,
	// which is discarded by FieldSelect when isInf is set.
	lambda := FieldMul(num, fieldInvAddchain(den))
	x3 := FieldSub(FieldSquare(lambda), FieldMul(fieldTwo, a.X))
	y3 := FieldSub(FieldMul(lambda, FieldSub(a.X, x3)), a.Y)

	isInf := a.Inf | fieldIsZero(a.Y)

	return &Point{
		X:   FieldSelect(isInf, x3, FieldZero()),
		Y:   FieldSelect(isInf, y3, FieldZero()),
		Inf: isInf,
	}
}

// Equal reports whether a and b encode the same curve point.
func Equal(a, b *Point) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Inf != 0 || b.Inf != 0 {
		return a.Inf != 0 && b.Inf != 0
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
