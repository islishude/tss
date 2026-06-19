package edwards25519

import (
	"errors"
	"slices"

	fed "filippo.io/edwards25519"
)

// WirePoint wraps a non-identity prime-order Ed25519 point for use with
// internal/wire's custom field kind.
type WirePoint struct {
	P *fed.Point
}

// MarshalWireValue returns the canonical compressed point encoding.
func (p WirePoint) MarshalWireValue() ([]byte, error) {
	if p.P == nil {
		return nil, errors.New("nil edwards25519 point")
	}
	validated, err := PointFromBytes(p.P.Bytes())
	if err != nil {
		return nil, err
	}
	return slices.Clone(validated.Bytes()), nil
}

// UnmarshalWireValue decodes a canonical non-identity prime-order point.
func (p *WirePoint) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil edwards25519 wire point")
	}
	decoded, err := PointFromBytes(in)
	if err != nil {
		return err
	}
	p.P = fed.NewIdentityPoint().Set(decoded)
	return nil
}

// WirePointAllowIdentity wraps a prime-order Ed25519 point for use with
// internal/wire's custom field kind. The identity point is allowed.
type WirePointAllowIdentity struct {
	P *fed.Point
}

// MarshalWireValue returns the canonical compressed point encoding.
func (p WirePointAllowIdentity) MarshalWireValue() ([]byte, error) {
	if p.P == nil {
		return nil, errors.New("nil edwards25519 point")
	}
	validated, err := PointFromBytesAllowIdentity(p.P.Bytes())
	if err != nil {
		return nil, err
	}
	return slices.Clone(validated.Bytes()), nil
}

// UnmarshalWireValue decodes a canonical prime-order point, allowing identity.
func (p *WirePointAllowIdentity) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil edwards25519 wire point")
	}
	decoded, err := PointFromBytesAllowIdentity(in)
	if err != nil {
		return err
	}
	p.P = fed.NewIdentityPoint().Set(decoded)
	return nil
}

// WireScalar wraps a public canonical Ed25519 scalar for use with
// internal/wire's custom field kind.
type WireScalar struct {
	S *fed.Scalar
}

// MarshalWireValue returns the canonical scalar encoding.
func (s WireScalar) MarshalWireValue() ([]byte, error) {
	if s.S == nil {
		return nil, errors.New("nil edwards25519 scalar")
	}
	validated, err := ScalarFromCanonical(s.S.Bytes())
	if err != nil {
		return nil, err
	}
	return slices.Clone(validated.Bytes()), nil
}

// UnmarshalWireValue decodes a canonical Ed25519 scalar.
func (s *WireScalar) UnmarshalWireValue(in []byte) error {
	if s == nil {
		return errors.New("nil edwards25519 wire scalar")
	}
	decoded, err := ScalarFromCanonical(in)
	if err != nil {
		return err
	}
	s.S = fed.NewScalar().Set(decoded)
	return nil
}
