package ed25519

import (
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func randomScalarPolynomial(reader io.Reader, threshold int, constant *edcurve.Scalar) ([]edcurve.Scalar, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
	}
	coeffs := make([]edcurve.Scalar, threshold)
	if constant != nil {
		coeffs[0] = *constant
	} else {
		x, err := edcurve.FiatRandomScalar(reader)
		if err != nil {
			return nil, err
		}
		coeffs[0] = x
	}
	for i := 1; i < threshold; i++ {
		x, err := edcurve.FiatRandomScalar(reader)
		if err != nil {
			return nil, err
		}
		coeffs[i] = x
	}
	return coeffs, nil
}

func evalScalarPolynomial(coeffs []edcurve.Scalar, id tss.PartyID) edcurve.Scalar {
	x := edcurve.FiatScalarFromUint64(uint64(id))
	acc := edcurve.ScalarZero()
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc = edcurve.ScalarMul(acc, x)
		acc = edcurve.ScalarAdd(acc, coeffs[i])
	}
	return acc
}

func lagrangeCoefficientScalar(id tss.PartyID, ids []tss.PartyID) (edcurve.Scalar, error) {
	if id == 0 {
		return edcurve.Scalar{}, errors.New("party id 0 is reserved")
	}
	xi := edcurve.FiatScalarFromUint64(uint64(id))
	num := edcurve.ScalarOne()
	den := edcurve.ScalarOne()
	seen := make(map[tss.PartyID]struct{}, len(ids))
	for _, other := range ids {
		if other == 0 {
			return edcurve.Scalar{}, errors.New("party id 0 is reserved")
		}
		if _, ok := seen[other]; ok {
			return edcurve.Scalar{}, fmt.Errorf("duplicate party id %d", other)
		}
		seen[other] = struct{}{}
		if other == id {
			continue
		}
		xj := edcurve.FiatScalarFromUint64(uint64(other))
		// The coefficient reconstructs the polynomial constant at x=0.
		num = edcurve.ScalarMul(num, xj)
		den = edcurve.ScalarMul(den, edcurve.ScalarSub(xj, xi))
	}
	if _, ok := seen[id]; !ok {
		return edcurve.Scalar{}, fmt.Errorf("party id %d not in interpolation set", id)
	}
	inv, err := edcurve.ScalarInv(den)
	if err != nil {
		return edcurve.Scalar{}, fmt.Errorf("non-invertible interpolation denominator: %w", err)
	}
	return edcurve.ScalarMul(num, inv), nil
}
