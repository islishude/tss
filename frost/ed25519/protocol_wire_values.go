package ed25519

import (
	"errors"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// nonceCommitmentPoint is a validated non-identity Ed25519 nonce commitment.
type nonceCommitmentPoint semanticPoint

func newNonceCommitmentPointFromPoint(point *fed.Point) (nonceCommitmentPoint, error) {
	value, err := newSemanticPointFromPoint(point, "nil nonce commitment point")
	if err != nil {
		return nonceCommitmentPoint{}, err
	}
	return nonceCommitmentPoint(value), nil
}

func newNonceCommitmentPointFromBytes(in []byte) (nonceCommitmentPoint, error) {
	point, err := newSemanticPointFromBytes(in)
	if err != nil {
		return nonceCommitmentPoint{}, err
	}
	return nonceCommitmentPoint(point), nil
}

// Point returns an independent mutable copy of the nonce commitment point.
func (p nonceCommitmentPoint) Point() *fed.Point {
	return semanticPoint(p).point()
}

// Bytes returns a caller-owned canonical encoding of the nonce commitment point.
func (p nonceCommitmentPoint) Bytes() []byte {
	return semanticPoint(p).bytes()
}

// Equal reports whether two nonce commitment points are equal.
func (p nonceCommitmentPoint) Equal(other nonceCommitmentPoint) bool {
	return semanticPoint(p).equal(semanticPoint(other))
}

// Validate checks that the nonce commitment is non-identity and prime order.
func (p nonceCommitmentPoint) Validate() error {
	return semanticPoint(p).validate("missing nonce commitment point")
}

// MarshalWireValue returns the canonical nonce commitment point encoding.
func (p nonceCommitmentPoint) MarshalWireValue() ([]byte, error) {
	return semanticPoint(p).marshalWireValue("missing nonce commitment point")
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
