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

// PublicKeyPoint is a validated, non-identity Ed25519 group public key.
type PublicKeyPoint struct {
	p *fed.Point
}

type publicKeyPoint = PublicKeyPoint

// NewPublicKeyPoint parses a canonical non-identity Ed25519 public key.
func NewPublicKeyPoint(in []byte) (PublicKeyPoint, error) {
	return newPublicKeyPointFromBytes(in)
}

func newPublicKeyPointFromBytes(in []byte) (publicKeyPoint, error) {
	p, err := edcurve.PointFromBytes(in)
	if err != nil {
		return publicKeyPoint{}, err
	}
	return publicKeyPoint{p: clonePoint(p)}, nil
}

func newPublicKeyPointFromPoint(p *fed.Point) (publicKeyPoint, error) {
	if p == nil {
		return publicKeyPoint{}, errors.New("nil public key point")
	}
	return newPublicKeyPointFromBytes(p.Bytes())
}

// Bytes returns a caller-owned canonical encoding of the public key point.
func (p PublicKeyPoint) Bytes() []byte {
	if p.p == nil {
		return nil
	}
	return p.p.Bytes()
}

// Point returns an independent mutable copy of the public key point.
func (p PublicKeyPoint) Point() *fed.Point {
	return clonePoint(p.p)
}

// Equal reports whether two public key points are equal.
func (p PublicKeyPoint) Equal(other PublicKeyPoint) bool {
	return pointEqual(p.p, other.p)
}

// Clone returns an independent copy of the public key point.
func (p PublicKeyPoint) Clone() PublicKeyPoint {
	return PublicKeyPoint{p: clonePoint(p.p)}
}

// IsZero reports whether the point has not been initialized.
func (p PublicKeyPoint) IsZero() bool {
	return p.p == nil
}

// Validate checks that the point is non-identity and in the prime-order subgroup.
func (p PublicKeyPoint) Validate() error {
	if p.p == nil {
		return errors.New("missing public key point")
	}
	_, err := edcurve.PointFromBytes(p.p.Bytes())
	return err
}

// MarshalWireValue returns the canonical wire encoding of the public key point.
func (p PublicKeyPoint) MarshalWireValue() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.Bytes(), nil
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
type VerificationSharePoint struct {
	p *fed.Point
}

type verificationSharePoint = VerificationSharePoint

// NewVerificationSharePoint parses a canonical Ed25519 verification share.
func NewVerificationSharePoint(in []byte) (VerificationSharePoint, error) {
	return newVerificationSharePointFromBytes(in)
}

func newVerificationSharePointFromBytes(in []byte) (verificationSharePoint, error) {
	p, err := edcurve.PointFromBytes(in)
	if err != nil {
		return verificationSharePoint{}, err
	}
	return verificationSharePoint{p: clonePoint(p)}, nil
}

func newVerificationSharePointFromPoint(p *fed.Point) (verificationSharePoint, error) {
	if p == nil {
		return verificationSharePoint{}, errors.New("nil verification share point")
	}
	return newVerificationSharePointFromBytes(p.Bytes())
}

// Bytes returns a caller-owned canonical encoding of the verification share.
func (p VerificationSharePoint) Bytes() []byte {
	if p.p == nil {
		return nil
	}
	return p.p.Bytes()
}

// Point returns an independent mutable copy of the verification share.
func (p VerificationSharePoint) Point() *fed.Point {
	return clonePoint(p.p)
}

// Equal reports whether two verification shares are equal.
func (p VerificationSharePoint) Equal(other VerificationSharePoint) bool {
	return pointEqual(p.p, other.p)
}

// Clone returns an independent copy of the verification share.
func (p VerificationSharePoint) Clone() VerificationSharePoint {
	return VerificationSharePoint{p: clonePoint(p.p)}
}

// IsZero reports whether the verification share has not been initialized.
func (p VerificationSharePoint) IsZero() bool {
	return p.p == nil
}

// Validate checks that the verification share is non-identity and in the
// prime-order subgroup.
func (p VerificationSharePoint) Validate() error {
	if p.p == nil {
		return errors.New("missing verification share point")
	}
	_, err := edcurve.PointFromBytes(p.p.Bytes())
	return err
}

// MarshalWireValue returns the canonical wire encoding of the verification share.
func (p VerificationSharePoint) MarshalWireValue() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.Bytes(), nil
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
