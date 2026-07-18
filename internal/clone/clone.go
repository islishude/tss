// Package clone provides internal helpers for making independently owned copies.
package clone

import (
	"math/big"
	"slices"
)

// ByteSlices returns a deep copy of a [][]byte slice. A nil input returns nil.
func ByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = slices.Clone(in[i])
	}
	return out
}

// Cloner is implemented by types that can return an independent clone of themselves.
type Cloner[T any] interface {
	Clone() T
}

// Slice returns a cloned copy of a slice of Cloner values.
//
// A nil input returns nil.
func Slice[T Cloner[T]](in []T) []T {
	if in == nil {
		return nil
	}

	out := make([]T, len(in))
	for i, value := range in {
		out[i] = value.Clone()
	}
	return out
}

// Map returns a cloned copy of a map whose values implement Cloner.
//
// A nil input returns nil. Map keys are copied as ordinary comparable values;
// only map values are cloned through Clone.
func Map[K comparable, V Cloner[V]](in map[K]V) map[K]V {
	if in == nil {
		return nil
	}
	out := make(map[K]V, len(in))
	for key, value := range in {
		out[key] = value.Clone()
	}
	return out
}

// BigInt returns a copy of x.
//
// If x is nil, BigInt returns nil. The returned *big.Int does not share
// mutable state with x, so modifying the returned value will not modify x.
func BigInt(x *big.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).Set(x)
}
