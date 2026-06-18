package tss

import (
	"encoding"
	"fmt"
)

// BinaryUnmarshalerWithLimits is implemented by binary decoders that require
// caller-provided resource limits.
type BinaryUnmarshalerWithLimits[L any] interface {
	UnmarshalBinaryWithLimits([]byte, L) error
}

// DecodeBinary decodes a binary-encoded value through its standard
// encoding.BinaryUnmarshaler implementation.
func DecodeBinary[T any](in []byte) (*T, error) {
	v := new(T)

	u, ok := any(v).(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, fmt.Errorf("%T does not implement encoding.BinaryUnmarshaler", v)
	}

	if err := u.UnmarshalBinary(in); err != nil {
		return nil, err
	}

	return v, nil
}

// DecodeBinaryValue decodes a binary-encoded value and returns it by value.
func DecodeBinaryValue[T any](in []byte) (T, error) {
	v, err := DecodeBinary[T](in)
	if err != nil {
		var zero T
		return zero, err
	}
	return *v, nil
}

// DecodeBinaryWithLimits decodes a binary-encoded value through its limits-aware
// unmarshaler implementation.
func DecodeBinaryWithLimits[T any, L any](in []byte, limits L) (*T, error) {
	v := new(T)

	u, ok := any(v).(BinaryUnmarshalerWithLimits[L])
	if !ok {
		return nil, fmt.Errorf("%T does not implement BinaryUnmarshalerWithLimits", v)
	}

	if err := u.UnmarshalBinaryWithLimits(in, limits); err != nil {
		return nil, err
	}

	return v, nil
}

// DecodeBinaryValueWithLimits decodes a limits-aware binary value and returns
// it by value.
func DecodeBinaryValueWithLimits[T any, L any](in []byte, limits L) (T, error) {
	v, err := DecodeBinaryWithLimits[T](in, limits)
	if err != nil {
		var zero T
		return zero, err
	}
	return *v, nil
}
