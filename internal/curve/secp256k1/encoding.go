package secp256k1

import "errors"

// PointBytes encodes p in canonical compressed SEC 1 form.
func PointBytes(p *Point) ([]byte, error) {
	if p == nil || p.Inf != 0 || !IsOnCurve(p) {
		return nil, errors.New("invalid secp256k1 point")
	}
	out := make([]byte, 33)
	raw := p.Y.Bytes()
	if raw[31]&1 == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[1:], p.X.Bytes())
	return out, nil
}

// MarshalWireValue encodes the point in canonical compressed SEC 1 form for
// internal/wire's custom field kind.
func (p *Point) MarshalWireValue() ([]byte, error) {
	return PointBytes(p)
}

// UnmarshalWireValue decodes canonical compressed SEC 1 point bytes for
// internal/wire's custom field kind.
func (p *Point) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil secp256k1 point")
	}
	q, err := PointFromBytes(in)
	if err != nil {
		return err
	}
	*p = *q
	return nil
}

// MarshalWireValue encodes the scalar as a fixed-width canonical value for
// internal/wire's custom field kind.
func (s Scalar) MarshalWireValue() ([]byte, error) {
	return s.Bytes(), nil
}

// UnmarshalWireValue decodes a fixed-width canonical scalar for
// internal/wire's custom field kind. Zero is accepted here; callers enforce
// context-specific non-zero requirements after unmarshaling.
func (s *Scalar) UnmarshalWireValue(in []byte) error {
	if s == nil {
		return errors.New("nil secp256k1 scalar")
	}
	v, err := ScalarFromBytesAllowZero(in)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// PointFromBytes parses canonical compressed SEC 1 point bytes.
func PointFromBytes(in []byte) (*Point, error) {
	if len(in) != 33 || (in[0] != 0x02 && in[0] != 0x03) {
		return nil, errors.New("secp256k1 point must be compressed")
	}
	x, err := FieldElementFromBytes(in[1:])
	if err != nil {
		return nil, err
	}
	y2 := FieldAdd(FieldMul(FieldSquare(x), x), fieldB)

	// sqrt: y = y2^((P+1)/4) since P ≡ 3 mod 4
	y := fieldSqrtAddchain(y2)
	if !FieldSquare(y).Equal(y2) {
		return nil, errors.New("point is not on curve")
	}
	wantOdd := in[0] == 0x03
	raw := y.Bytes()
	if (raw[31]&1 == 1) != wantOdd {
		y = FieldNeg(y)
	}
	p := &Point{X: x, Y: y}
	if !IsOnCurve(p) {
		return nil, errors.New("point is not on curve")
	}
	return p, nil
}
