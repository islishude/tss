package tss

import "slices"

// CloneByteSlices returns a deep copy of a [][]byte slice. A nil input returns nil.
func CloneByteSlices(in [][]byte) [][]byte {
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

// CloneSlice returns a cloned copy of a slice of Cloner values.
//
// It returns nil when in is nil or empty.
func CloneSlice[T Cloner[T]](in []T) []T {
	if in == nil {
		return nil
	}

	out := make([]T, len(in))
	for i, share := range in {
		out[i] = share.Clone()
	}
	return out
}
