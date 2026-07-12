package signprep

import secp "github.com/islishude/tss/internal/curve/secp256k1"

func optionalPointFromBytes(encoded []byte) (*secp.Point, error) {
	if len(encoded) == 0 {
		return secp.NewInfinity(), nil
	}
	point, err := secp.PointFromBytes(encoded)
	if err != nil {
		return nil, err
	}
	return point, nil
}

func subtractPoints(left, right *secp.Point) *secp.Point {
	negRight := secp.Clone(right)
	if negRight.Inf == 0 {
		negRight.Y = secp.FieldNeg(negRight.Y)
	}
	return secp.Add(left, negRight)
}
