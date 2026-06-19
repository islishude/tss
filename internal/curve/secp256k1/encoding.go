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

// WirePoint wraps a *Point for use with internal/wire's custom field kind.
// It implements MarshalWireValue / UnmarshalWireValue via Go structural typing
// (no import of internal/wire required). The zero value has a nil Point and
// will be rejected on marshal.
type WirePoint struct {
	P *Point
}

// MarshalWireValue encodes the point in canonical compressed SEC 1 form.
func (p WirePoint) MarshalWireValue() ([]byte, error) {
	return PointBytes(p.P)
}

// UnmarshalWireValue decodes canonical compressed SEC 1 point bytes.
func (p *WirePoint) UnmarshalWireValue(in []byte) error {
	q, err := PointFromBytes(in)
	if err != nil {
		return err
	}
	p.P = q
	return nil
}

// WireScalar wraps a Scalar for use with internal/wire's custom field kind.
// It accepts the zero scalar on decode; callers enforce context-specific
// non-zero requirements after unmarshaling.
type WireScalar struct {
	S Scalar
}

// MarshalWireValue encodes the scalar as a fixed-width canonical value.
func (s WireScalar) MarshalWireValue() ([]byte, error) {
	return s.S.Bytes(), nil
}

// UnmarshalWireValue decodes a fixed-width canonical scalar.
func (s *WireScalar) UnmarshalWireValue(in []byte) error {
	v, err := ScalarFromBytesAllowZero(in)
	if err != nil {
		return err
	}
	s.S = v
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
