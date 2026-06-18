package secret

import (
	"crypto/subtle"
	"errors"
)

const signedIntRedacted = "<secret.SignedInt:redacted>"

// SignedInt is a fixed-width signed secret integer. The sign is stored
// separately from a fixed-width magnitude so callers can perform
// constant-time sign selection without exposing a variable-width encoding.
type SignedInt struct {
	negative  byte
	magnitude []byte
}

// NewSignedInt creates a fixed-width signed secret integer. Magnitude must be
// exactly fixedLen bytes. Negative zero is rejected.
func NewSignedInt(negative bool, magnitude []byte, fixedLen int) (*SignedInt, error) {
	if fixedLen <= 0 {
		return nil, errors.New("secret signed integer length must be positive")
	}
	if len(magnitude) != fixedLen {
		return nil, errors.New("secret signed integer magnitude has wrong length")
	}
	var sign byte
	if negative {
		sign = 1
		if subtle.ConstantTimeCompare(magnitude, make([]byte, fixedLen)) == 1 {
			return nil, errors.New("secret signed integer cannot encode negative zero")
		}
	}
	out := &SignedInt{
		negative:  sign,
		magnitude: make([]byte, fixedLen),
	}
	copy(out.magnitude, magnitude)
	return out, nil
}

// FixedMagnitude returns a copy of the fixed-width magnitude.
func (s *SignedInt) FixedMagnitude() []byte {
	if s == nil {
		return nil
	}
	if len(s.magnitude) == 0 {
		return nil
	}
	out := make([]byte, len(s.magnitude))
	copy(out, s.magnitude)
	return out
}

// FixedLen returns the fixed byte length of the magnitude.
func (s *SignedInt) FixedLen() int {
	if s == nil {
		return 0
	}
	return len(s.magnitude)
}

// SelectBySign returns nonNegative when s is non-negative and negative when s
// is negative. Both inputs must have the same length. Selection is constant
// time with respect to the secret sign.
func (s *SignedInt) SelectBySign(nonNegative, negative []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil secret signed integer")
	}
	if len(s.magnitude) == 0 {
		return nil, errors.New("destroyed secret signed integer")
	}
	if s.negative > 1 {
		return nil, errors.New("invalid secret signed integer sign")
	}
	if len(nonNegative) != len(negative) {
		return nil, errors.New("secret signed integer selection length mismatch")
	}
	out := make([]byte, len(nonNegative))
	copy(out, nonNegative)
	subtle.ConstantTimeCopy(int(s.negative), out, negative)
	return out, nil
}

// Clone returns an independent copy of the signed integer.
func (s *SignedInt) Clone() *SignedInt {
	if s == nil {
		return nil
	}
	out := &SignedInt{
		negative:  s.negative,
		magnitude: make([]byte, len(s.magnitude)),
	}
	copy(out.magnitude, s.magnitude)
	return out
}

// Equal reports whether s and t encode the same signed integer.
func (s *SignedInt) Equal(t *SignedInt) bool {
	if s == nil || t == nil {
		return s == t
	}
	if len(s.magnitude) != len(t.magnitude) {
		return false
	}
	signEqual := subtle.ConstantTimeByteEq(s.negative, t.negative)
	magnitudeEqual := subtle.ConstantTimeCompare(s.magnitude, t.magnitude)
	return signEqual&magnitudeEqual == 1
}

// Destroy clears the sign and magnitude in place.
func (s *SignedInt) Destroy() {
	if s == nil {
		return
	}
	s.negative = 0
	clear(s.magnitude)
	s.magnitude = nil
}

// MarshalJSON rejects JSON encoding of signed secret integers.
func (s *SignedInt) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret.SignedInt must not be JSON-encoded")
}

// UnmarshalJSON rejects JSON decoding of signed secret integers.
func (s *SignedInt) UnmarshalJSON([]byte) error {
	return errors.New("secret.SignedInt must not be JSON-decoded")
}

// MarshalBinary rejects ordinary binary serialization of signed secret integers.
func (s *SignedInt) MarshalBinary() ([]byte, error) {
	return nil, errors.New("secret.SignedInt must not be binary-encoded")
}

// UnmarshalBinary rejects ordinary binary decoding of signed secret integers.
func (s *SignedInt) UnmarshalBinary([]byte) error {
	return errors.New("secret.SignedInt must not be binary-decoded")
}

// String returns a redacted representation.
func (s *SignedInt) String() string {
	return signedIntRedacted
}

// GoString returns a redacted representation.
func (s *SignedInt) GoString() string {
	return signedIntRedacted
}
