package ed25519

import (
	"errors"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// nonceCommitmentPoint is a validated non-identity Ed25519 nonce commitment.
type nonceCommitmentPoint struct {
	p *fed.Point
}

func newNonceCommitmentPointFromPoint(point *fed.Point) (nonceCommitmentPoint, error) {
	if point == nil {
		return nonceCommitmentPoint{}, errors.New("nil nonce commitment point")
	}
	return newNonceCommitmentPointFromBytes(point.Bytes())
}

func newNonceCommitmentPointFromBytes(in []byte) (nonceCommitmentPoint, error) {
	point, err := edcurve.PointFromBytes(in)
	if err != nil {
		return nonceCommitmentPoint{}, err
	}
	return nonceCommitmentPoint{p: clonePoint(point)}, nil
}

// Point returns an independent mutable copy of the nonce commitment point.
func (p nonceCommitmentPoint) Point() *fed.Point {
	return clonePoint(p.p)
}

// Bytes returns a caller-owned canonical encoding of the nonce commitment point.
func (p nonceCommitmentPoint) Bytes() []byte {
	if p.p == nil {
		return nil
	}
	return p.p.Bytes()
}

// Equal reports whether two nonce commitment points are equal.
func (p nonceCommitmentPoint) Equal(other nonceCommitmentPoint) bool {
	return pointEqual(p.p, other.p)
}

// Validate checks that the nonce commitment is non-identity and prime order.
func (p nonceCommitmentPoint) Validate() error {
	if p.p == nil {
		return errors.New("missing nonce commitment point")
	}
	_, err := edcurve.PointFromBytes(p.p.Bytes())
	return err
}

// MarshalWireValue returns the canonical nonce commitment point encoding.
func (p nonceCommitmentPoint) MarshalWireValue() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.Bytes(), nil
}

// UnmarshalWireValue decodes a canonical nonce commitment point.
func (p *nonceCommitmentPoint) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil nonce commitment point")
	}
	decoded, err := newNonceCommitmentPointFromBytes(in)
	if err != nil {
		return err
	}
	*p = decoded
	return nil
}

// canonicalScalar is a validated canonical public Ed25519 scalar.
type canonicalScalar struct {
	s *fed.Scalar
}

func newCanonicalScalar(scalar *fed.Scalar) (canonicalScalar, error) {
	if scalar == nil {
		return canonicalScalar{}, errors.New("nil canonical scalar")
	}
	return newCanonicalScalarFromBytes(scalar.Bytes())
}

func newCanonicalScalarFromBytes(in []byte) (canonicalScalar, error) {
	scalar, err := edcurve.ScalarFromCanonical(in)
	if err != nil {
		return canonicalScalar{}, err
	}
	return canonicalScalar{s: fed.NewScalar().Set(scalar)}, nil
}

// Scalar returns an independent mutable copy of the canonical scalar.
func (s canonicalScalar) Scalar() *fed.Scalar {
	if s.s == nil {
		return nil
	}
	return fed.NewScalar().Set(s.s)
}

// Bytes returns a caller-owned canonical scalar encoding.
func (s canonicalScalar) Bytes() []byte {
	if s.s == nil {
		return nil
	}
	return s.s.Bytes()
}

// Validate checks that the scalar has a canonical Ed25519 encoding.
func (s canonicalScalar) Validate() error {
	if s.s == nil {
		return errors.New("missing canonical scalar")
	}
	_, err := edcurve.ScalarFromCanonical(s.s.Bytes())
	return err
}

// MarshalWireValue returns the canonical scalar encoding.
func (s canonicalScalar) MarshalWireValue() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// UnmarshalWireValue decodes a canonical Ed25519 scalar.
func (s *canonicalScalar) UnmarshalWireValue(in []byte) error {
	if s == nil {
		return errors.New("nil canonical scalar")
	}
	decoded, err := newCanonicalScalarFromBytes(in)
	if err != nil {
		return err
	}
	*s = decoded
	return nil
}
