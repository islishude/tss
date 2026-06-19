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

// CloneMap returns a cloned copy of a map whose values implement Cloner.
//
// A nil input returns nil. Map keys are copied as ordinary comparable values;
// only map values are cloned through Clone.
func CloneMap[K comparable, V Cloner[V]](in map[K]V) map[K]V {
	if in == nil {
		return nil
	}
	out := make(map[K]V, len(in))
	for key, value := range in {
		out[key] = value.Clone()
	}
	return out
}
