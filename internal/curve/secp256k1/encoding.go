package secp256k1

import "errors"

// PointBytes encodes p in canonical compressed SEC 1 form.
func PointBytes(p *Point) ([]byte, error) {
	if p == nil || p.Inf || !IsOnCurve(p) {
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
