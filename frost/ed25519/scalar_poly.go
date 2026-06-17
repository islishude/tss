package ed25519

import (
	"errors"
	"fmt"
	"io"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func randomScalarPolynomial(reader io.Reader, threshold int, constant *fed.Scalar) ([]*fed.Scalar, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
	}
	coeffs := make([]*fed.Scalar, threshold)
	if constant != nil {
		coeffs[0] = fed.NewScalar().Set(constant)
	} else {
		x, err := edcurve.RandomScalar(reader)
		if err != nil {
			return nil, err
		}
		coeffs[0] = x
	}
	for i := 1; i < threshold; i++ {
		x, err := edcurve.RandomScalar(reader)
		if err != nil {
			return nil, err
		}
		coeffs[i] = x
	}
	return coeffs, nil
}

func evalScalarPolynomial(coeffs []*fed.Scalar, id tss.PartyID) *fed.Scalar {
	x := edcurve.ScalarFromUint64(uint64(id))
	acc := fed.NewScalar()
	for _, coeff := range slices.Backward(coeffs) {
		acc.Multiply(acc, x)
		acc.Add(acc, coeff)
	}
	return acc
}

func lagrangeCoefficientScalar(id tss.PartyID, ids tss.PartySet) (*fed.Scalar, error) {
	if id == 0 {
		return nil, errors.New("party id 0 is reserved")
	}
	xi := edcurve.ScalarFromUint64(uint64(id))
	num := edcurve.ScalarOne()
	den := edcurve.ScalarOne()
	seen := make(map[tss.PartyID]struct{}, len(ids))
	for _, other := range ids {
		if other == 0 {
			return nil, errors.New("party id 0 is reserved")
		}
		if _, ok := seen[other]; ok {
			return nil, fmt.Errorf("duplicate party id %d", other)
		}
		seen[other] = struct{}{}
		if other == id {
			continue
		}
		xj := edcurve.ScalarFromUint64(uint64(other))
		// The coefficient reconstructs the polynomial constant at x=0.
		num.Multiply(num, xj)
		diff := fed.NewScalar().Subtract(xj, xi)
		den.Multiply(den, diff)
	}
	if _, ok := seen[id]; !ok {
		return nil, fmt.Errorf("party id %d not in interpolation set", id)
	}
	if den.Equal(edcurve.ScalarZero()) == 1 {
		return nil, fmt.Errorf("non-invertible interpolation denominator")
	}
	return fed.NewScalar().Multiply(num, fed.NewScalar().Invert(den)), nil
}
