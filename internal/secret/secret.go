// Package secret provides fixed-length scalar types for cryptographic secrets.
// Types in this package intentionally hide their internal representation and
// do not expose *big.Int, variable-length Bytes(), String(), or JSON encoding.
package secret

import (
	"errors"
	"fmt"
)

// Scalar is a fixed-length secret scalar. It deliberately exposes no variable-length
// or human-readable representation to avoid accidental logging, serialization,
// or non-constant-time conversion of secret material.
type Scalar struct {
	buf []byte
}

// NewScalar creates a Scalar from big-endian bytes padded or truncated to fixedLen.
// The input is copied so the caller retains ownership of data.
func NewScalar(data []byte, fixedLen int) (*Scalar, error) {
	if fixedLen <= 0 {
		return nil, errors.New("secret scalar length must be positive")
	}
	if len(data) == 0 {
		return nil, errors.New("secret scalar data must not be empty")
	}
	buf := make([]byte, fixedLen)
	if len(data) >= fixedLen {
		copy(buf, data[len(data)-fixedLen:])
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

// Destroy zeros the internal buffer in place.
func (s *Scalar) Destroy() {
	if s == nil {
		return
	}
	clear(s.buf)
}

// Equal reports whether s and t encode the same scalar in constant time.
func (s *Scalar) Equal(t *Scalar) bool {
	if s == nil || t == nil {
		return s == t
	}
	if len(s.buf) != len(t.buf) {
		return false
	}
	var acc byte
	for i := range s.buf {
		acc |= s.buf[i] ^ t.buf[i]
	}
	return acc == 0
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
