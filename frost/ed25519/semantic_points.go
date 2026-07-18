package ed25519

import (
	"encoding/json"
	"errors"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func clonePoint(p *fed.Point) *fed.Point {
	if p == nil {
		return nil
	}
	return fed.NewIdentityPoint().Set(p)
}

func pointEqual(a, b *fed.Point) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(b) == 1
}

// semanticPoint centralizes the copy, equality, canonical encoding, and
// non-identity validation shared by the protocol's semantic point wrappers.
// The named wrappers remain distinct types so their roles cannot be mixed.
type semanticPoint struct {
	p *fed.Point
}

func newSemanticPointFromBytes(in []byte) (semanticPoint, error) {
	p, err := edcurve.PointFromBytes(in)
	if err != nil {
		return semanticPoint{}, err
	}
	return semanticPoint{p: clonePoint(p)}, nil
}

func newSemanticPointFromPoint(p *fed.Point, nilError string) (semanticPoint, error) {
	if p == nil {
		return semanticPoint{}, errors.New(nilError)
	}
	return newSemanticPointFromBytes(p.Bytes())
}

func (p semanticPoint) bytes() []byte {
	if p.p == nil {
		return nil
	}
	return p.p.Bytes()
}

func (p semanticPoint) point() *fed.Point { return clonePoint(p.p) }

func (p semanticPoint) equal(other semanticPoint) bool { return pointEqual(p.p, other.p) }

func (p semanticPoint) clone() semanticPoint { return semanticPoint{p: clonePoint(p.p)} }

func (p semanticPoint) isZero() bool { return p.p == nil }

func (p semanticPoint) validate(missingError string) error {
	if p.p == nil {
		return errors.New(missingError)
	}
	_, err := edcurve.PointFromBytes(p.p.Bytes())
	return err
}

func (p semanticPoint) marshalWireValue(missingError string) ([]byte, error) {
	if err := p.validate(missingError); err != nil {
		return nil, err
	}
	return p.bytes(), nil
}

// PublicKeyPoint is a validated, non-identity Ed25519 group public key.
type PublicKeyPoint semanticPoint

// NewPublicKeyPoint parses a canonical non-identity Ed25519 public key.
func NewPublicKeyPoint(in []byte) (PublicKeyPoint, error) {
	return newPublicKeyPointFromBytes(in)
}

func newPublicKeyPointFromBytes(in []byte) (PublicKeyPoint, error) {
	p, err := newSemanticPointFromBytes(in)
	if err != nil {
		return PublicKeyPoint{}, err
	}
	return PublicKeyPoint(p), nil
}

func newPublicKeyPointFromPoint(p *fed.Point) (PublicKeyPoint, error) {
	point, err := newSemanticPointFromPoint(p, "nil public key point")
	if err != nil {
		return PublicKeyPoint{}, err
	}
	return PublicKeyPoint(point), nil
}

// Bytes returns a caller-owned canonical encoding of the public key point.
func (p PublicKeyPoint) Bytes() []byte {
	return semanticPoint(p).bytes()
}

// Point returns an independent mutable copy of the public key point.
func (p PublicKeyPoint) Point() *fed.Point {
	return semanticPoint(p).point()
}

// Equal reports whether two public key points are equal.
func (p PublicKeyPoint) Equal(other PublicKeyPoint) bool {
	return semanticPoint(p).equal(semanticPoint(other))
}

// Clone returns an independent copy of the public key point.
func (p PublicKeyPoint) Clone() PublicKeyPoint {
	return PublicKeyPoint(semanticPoint(p).clone())
}

// IsZero reports whether the point has not been initialized.
func (p PublicKeyPoint) IsZero() bool {
	return semanticPoint(p).isZero()
}

// Validate checks that the point is non-identity and in the prime-order subgroup.
func (p PublicKeyPoint) Validate() error {
	return semanticPoint(p).validate("missing public key point")
}

// MarshalWireValue returns the canonical wire encoding of the public key point.
func (p PublicKeyPoint) MarshalWireValue() ([]byte, error) {
	return semanticPoint(p).marshalWireValue("missing public key point")
}

// UnmarshalWireValue decodes a canonical non-identity public key point.
func (p *PublicKeyPoint) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil public key point")
	}
	point, err := newPublicKeyPointFromBytes(in)
	if err != nil {
		return err
	}
	*p = point
	return nil
}

// MarshalJSON encodes the public key point as canonical public-key bytes.
func (p PublicKeyPoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Bytes())
}

// UnmarshalJSON decodes and validates canonical public-key bytes.
func (p *PublicKeyPoint) UnmarshalJSON(in []byte) error {
	if p == nil {
		return errors.New("nil public key point")
	}
	var encoded []byte
	if err := json.Unmarshal(in, &encoded); err != nil {
		return err
	}
	point, err := newPublicKeyPointFromBytes(encoded)
	if err != nil {
		return err
	}
	*p = point
	return nil
}

// VerificationSharePoint is a validated Ed25519 verification-share point.
//
// FROST verification shares are non-identity prime-order elements. Malformed
// encodings, the identity, and non-prime-order torsion points are rejected.
type VerificationSharePoint semanticPoint

// NewVerificationSharePoint parses a canonical Ed25519 verification share.
func NewVerificationSharePoint(in []byte) (VerificationSharePoint, error) {
	return newVerificationSharePointFromBytes(in)
}

func newVerificationSharePointFromBytes(in []byte) (VerificationSharePoint, error) {
	p, err := newSemanticPointFromBytes(in)
	if err != nil {
		return VerificationSharePoint{}, err
	}
	return VerificationSharePoint(p), nil
}

func newVerificationSharePointFromPoint(p *fed.Point) (VerificationSharePoint, error) {
	point, err := newSemanticPointFromPoint(p, "nil verification share point")
	if err != nil {
		return VerificationSharePoint{}, err
	}
	return VerificationSharePoint(point), nil
}

// Bytes returns a caller-owned canonical encoding of the verification share.
func (p VerificationSharePoint) Bytes() []byte {
	return semanticPoint(p).bytes()
}

// Point returns an independent mutable copy of the verification share.
func (p VerificationSharePoint) Point() *fed.Point {
	return semanticPoint(p).point()
}

// Equal reports whether two verification shares are equal.
func (p VerificationSharePoint) Equal(other VerificationSharePoint) bool {
	return semanticPoint(p).equal(semanticPoint(other))
}

// Clone returns an independent copy of the verification share.
func (p VerificationSharePoint) Clone() VerificationSharePoint {
	return VerificationSharePoint(semanticPoint(p).clone())
}

// IsZero reports whether the verification share has not been initialized.
func (p VerificationSharePoint) IsZero() bool {
	return semanticPoint(p).isZero()
}

// Validate checks that the verification share is non-identity and in the
// prime-order subgroup.
func (p VerificationSharePoint) Validate() error {
	return semanticPoint(p).validate("missing verification share point")
}

// MarshalWireValue returns the canonical wire encoding of the verification share.
func (p VerificationSharePoint) MarshalWireValue() ([]byte, error) {
	return semanticPoint(p).marshalWireValue("missing verification share point")
}

// UnmarshalWireValue decodes a canonical verification-share point.
func (p *VerificationSharePoint) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil verification share point")
	}
	point, err := newVerificationSharePointFromBytes(in)
	if err != nil {
		return err
	}
	*p = point
	return nil
}

// MarshalJSON encodes the verification-share point as canonical point bytes.
func (p VerificationSharePoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Bytes())
}

// UnmarshalJSON decodes and validates canonical verification-share point bytes.
func (p *VerificationSharePoint) UnmarshalJSON(in []byte) error {
	if p == nil {
		return errors.New("nil verification share point")
	}
	var encoded []byte
	if err := json.Unmarshal(in, &encoded); err != nil {
		return err
	}
	point, err := newVerificationSharePointFromBytes(encoded)
	if err != nil {
		return err
	}
	*p = point
	return nil
}
