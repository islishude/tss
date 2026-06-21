package secp256k1

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// Polynomial is a secp256k1 Shamir polynomial in coefficient order.
// The coefficient at index 0 is the constant term.
type Polynomial []secp.Scalar

// RandomPolynomial returns coefficients for a degree threshold-1 polynomial.
// When constant is nil, the constant term is sampled as a non-zero scalar. When
// constant is provided, it is used verbatim and may be zero for refresh shares.
func RandomPolynomial(reader io.Reader, threshold int, constant *secp.Scalar) (Polynomial, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
	}
	coeffs := make(Polynomial, threshold)
	if constant != nil {
		coeffs[0] = *constant
	} else {
		x, err := secp.RandomScalar(reader)
		if err != nil {
			return nil, err
		}
		coeffs[0] = x
	}
	for i := 1; i < threshold; i++ {
		x, err := secp.RandomScalar(reader)
		if err != nil {
			return nil, err
		}
		coeffs[i] = x
	}
	return coeffs, nil
}

// Eval evaluates poly at the participant identifier modulo the secp256k1 order.
func Eval(poly Polynomial, id tss.PartyID) secp.Scalar {
	x := secp.ScalarFromUint64(uint64(id))
	acc := secp.ScalarZero()
	for _, p := range slices.Backward(poly) {
		acc = secp.ScalarMul(acc, x)
		acc = secp.ScalarAdd(acc, p)
	}
	return acc
}

// LagrangeCoefficient returns the coefficient for reconstructing at x=0.
func LagrangeCoefficient(id tss.PartyID, ids tss.PartySet) (secp.Scalar, error) {
	if id == 0 {
		return secp.Scalar{}, errors.New("party id 0 is reserved")
	}
	xi := secp.ScalarFromUint64(uint64(id))
	num := secp.ScalarOne()
	den := secp.ScalarOne()
	seen := make(map[tss.PartyID]struct{}, len(ids))
	for _, other := range ids {
		if other == 0 {
			return secp.Scalar{}, errors.New("party id 0 is reserved")
		}
		if _, ok := seen[other]; ok {
			return secp.Scalar{}, fmt.Errorf("duplicate party id %d", other)
		}
		seen[other] = struct{}{}
		if other == id {
			continue
		}
		xj := secp.ScalarFromUint64(uint64(other))
		num = secp.ScalarMul(num, xj)
		den = secp.ScalarMul(den, secp.ScalarSub(xj, xi))
	}
	if _, ok := seen[id]; !ok {
		return secp.Scalar{}, fmt.Errorf("party id %d not in interpolation set", id)
	}
	inv, err := secp.ScalarInvert(den)
	if err != nil {
		return secp.Scalar{}, errors.New("non-invertible interpolation denominator")
	}
	return secp.ScalarMul(num, inv), nil
}
