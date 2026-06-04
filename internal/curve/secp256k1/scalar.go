package secp256k1

import (
	"crypto/rand"
	"io"
	"math/big"
)

// orderBig is the precomputed subgroup order (N cannot be a Scalar since Scalars are < N).
var orderBig = new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41})

// Order returns the secp256k1 subgroup order.
func Order() *big.Int {
	return new(big.Int).Set(orderBig)
}

// ScalarBaseMult returns k*G modulo the subgroup order.
func ScalarBaseMult(k Scalar) *Point {
	return ScalarMult(G, k)
}

// ScalarMult returns k*p using a constant-time double-and-add routine.
// Every iteration evaluates both Double and Add unconditionally and
// selects the result via PointSelect so the scalar bits never appear
// in control flow.
func ScalarMult(p *Point, k Scalar) *Point {
	if k.IsZero() || p == nil || p.Inf != 0 {
		return NewInfinity()
	}
	kB := k.Bytes()
	base := Clone(p)
	acc := NewInfinity()

	for byteIdx := range 32 {
		b := kB[byteIdx]
		for bit := 7; bit >= 0; bit-- {
			nextDouble := Double(acc)
			nextAdd := Add(nextDouble, base)
			bitVal := uint64((b >> bit) & 1)
			// bitVal==0: keep nextDouble.  bitVal==1: pick nextAdd.
			acc = PointSelect(bitVal, nextDouble, nextAdd)
		}
	}
	// Normalise the accumulator without branching: when Inf is set,
	// zero X and Y so the caller sees a canonical point-at-infinity.
	acc.X = FieldSelect(acc.Inf, acc.X, FieldZero())
	acc.Y = FieldSelect(acc.Inf, acc.Y, FieldZero())
	return acc
}

// RandomScalar returns a non-zero scalar in [1, N).
func RandomScalar(reader io.Reader) (Scalar, error) {
	if reader == nil {
		reader = rand.Reader
	}
	for {
		var raw [32]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return Scalar{}, err
		}
		s, err := ScalarFromBytes(raw[:])
		if err != nil {
			continue
		}
		return s, nil
	}
}
