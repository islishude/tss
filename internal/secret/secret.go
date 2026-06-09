// Package secret provides fixed-length scalar types for cryptographic secrets.
// Types in this package intentionally hide their internal representation and
// do not expose *big.Int, variable-length Bytes(), String(), or JSON encoding.
package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
)

// Scalar is a fixed-length secret scalar. It deliberately exposes no variable-length
// or human-readable representation to avoid accidental logging, serialization,
// or non-constant-time conversion of secret material.
type Scalar struct {
	buf []byte
}

// NewScalar creates a Scalar from big-endian bytes. The input must be exactly
// fixedLen bytes or shorter (left-padded with zeros). Inputs longer than fixedLen
// are rejected to prevent silent truncation of high bytes.
// The input is copied so the caller retains ownership of data.
func NewScalar(data []byte, fixedLen int) (*Scalar, error) {
	if fixedLen <= 0 {
		return nil, errors.New("secret scalar length must be positive")
	}
	if len(data) == 0 {
		return nil, errors.New("secret scalar data must not be empty")
	}
	if len(data) > fixedLen {
		return nil, fmt.Errorf("secret scalar data too long: %d bytes, max %d", len(data), fixedLen)
	}
	buf := make([]byte, fixedLen)
	if len(data) == fixedLen {
		copy(buf, data)
	} else {
		copy(buf[fixedLen-len(data):], data)
	}
	return &Scalar{buf: buf}, nil
}

// FixedBytes returns a copy of the fixed-length big-endian encoding.
func (s *Scalar) FixedBytes() []byte {
	if s == nil {
		return nil
	}
	out := make([]byte, len(s.buf))
	copy(out, s.buf)
	return out
}

// FixedLen returns the fixed byte length of this scalar.
func (s *Scalar) FixedLen() int {
	if s == nil {
		return 0
	}
	return len(s.buf)
}

// MarshalJSON rejects JSON encoding of secret scalars to prevent accidental
// logging or serialization of secret material.
func (s *Scalar) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret.Scalar must not be JSON-encoded")
}

// MarshalWireValue returns the fixed-length big-endian encoding for use by
// internal/wire's "custom" field kind. It implements the wire.ValueMarshaler
// interface via Go structural typing (no import of internal/wire required).
func (s *Scalar) MarshalWireValue() ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil scalar")
	}
	out := s.FixedBytes()
	if len(out) == 0 {
		return nil, errors.New("empty scalar")
	}
	return out, nil
}

// UnmarshalWireValue sets the scalar from fixed-length big-endian bytes for
// use by internal/wire's "custom" field kind. It implements the
// wire.ValueUnmarshaler interface via Go structural typing.
// The input is copied so the caller retains ownership.
func (s *Scalar) UnmarshalWireValue(in []byte) error {
	if s == nil {
		return errors.New("nil scalar")
	}
	if len(in) == 0 {
		return errors.New("empty scalar")
	}
	s.buf = make([]byte, len(in))
	copy(s.buf, in)
	return nil
}

// Clone returns an independent copy of the scalar, or nil if s is nil.
func (s *Scalar) Clone() *Scalar {
	if s == nil {
		return nil
	}
	return &Scalar{buf: slices.Clone(s.buf)}
}

// Destroy zeros the internal buffer in place.
func (s *Scalar) Destroy() {
	if s == nil {
		return
	}
	clear(s.buf)
	s.buf = nil
}

// Equal reports whether s and t encode the same scalar in constant time.
func (s *Scalar) Equal(t *Scalar) bool {
	if s == nil || t == nil {
		return s == t
	}
	return subtle.ConstantTimeCompare(s.buf, t.buf) == 1
}

// MarshalBinary returns a compact big-endian encoding with no leading zero byte.
// This matches the historical wire format used by paillier private-key TLV records.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil scalar")
	}
	b := s.FixedBytes()
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	out := make([]byte, len(b)-i)
	copy(out, b[i:])
	if len(out) == 0 || out[0] == 0 {
		return nil, errors.New("scalar encodes to empty or zero-leading")
	}
	return out, nil
}

// UnmarshalScalar parses a compact big-endian encoding into a fixed-length Scalar.
func UnmarshalScalar(data []byte, fixedLen int) (*Scalar, error) {
	if len(data) == 0 {
		return nil, errors.New("empty scalar data")
	}
	if data[0] == 0 {
		return nil, errors.New("non-minimal scalar encoding")
	}
	if len(data) > fixedLen {
		return nil, fmt.Errorf("scalar too large: %d bytes, max %d", len(data), fixedLen)
	}
	return NewScalar(data, fixedLen)
}
