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

// ScalarMult returns k*p using a simple double-and-add routine.
func ScalarMult(p *Point, k Scalar) *Point {
	if k.IsZero() || p == nil || p.Inf {
		return NewInfinity()
	}
	kB := k.Bytes()
	acc := NewInfinity()
	base := Clone(p)
	for byteIdx := range 32 {
		b := kB[byteIdx]
		for bit := 7; bit >= 0; bit-- {
			acc = Double(acc)
			if b&(1<<bit) != 0 {
				acc = Add(acc, base)
			}
		}
	}
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

// ParseScalar parses a canonical 32-byte non-zero scalar.
func ParseScalar(in []byte) (Scalar, error) {
	return ScalarFromBytes(in)
}

// ScalarBytes returns x as a fixed-width 32-byte big-endian scalar.
func ScalarBytes(x Scalar) []byte {
	return x.Bytes()
}
