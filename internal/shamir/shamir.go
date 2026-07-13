// Package shamir implements Shamir secret sharing over the secp256k1 scalar
// field for CGGMP21.
//
// This package is intentionally not generic. All coefficients, shares, and
// interpolation coefficients are internal/curve/secp256k1.Scalar values.
package shamir

import (
	"errors"
	"fmt"
	"io"
	"slices"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// Polynomial is a secp256k1 Shamir polynomial in coefficient order.
// The coefficient at index 0 is the constant term.
type Polynomial []secp.Scalar

// Identifier is one non-zero scalar evaluation point for a Shamir epoch.
// Its zero value is invalid; construct identifiers with [IdentifierFromBytes].
type Identifier struct {
	scalar secp.Scalar
}

// IdentifierFromBytes parses a canonical, non-zero secp256k1 scalar identifier.
func IdentifierFromBytes(in []byte) (Identifier, error) {
	scalar, err := secp.ScalarFromBytes(in)
	if err != nil {
		return Identifier{}, fmt.Errorf("invalid Shamir identifier: %w", err)
	}
	return Identifier{scalar: scalar}, nil
}

// Bytes returns a fixed-width caller-owned encoding of id.
func (id Identifier) Bytes() []byte {
	return id.scalar.Bytes()
}

// Equal reports whether id and other are the same scalar identifier.
func (id Identifier) Equal(other Identifier) bool {
	return id.scalar.Equal(other.scalar)
}

// Validate rejects the invalid zero-value identifier.
func (id Identifier) Validate() error {
	if id.scalar.IsZero() {
		return errors.New("shamir identifier is zero")
	}
	return nil
}

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

// EvalAt evaluates poly at an explicit epoch identifier.
func EvalAt(poly Polynomial, id Identifier) (secp.Scalar, error) {
	if err := id.Validate(); err != nil {
		return secp.Scalar{}, err
	}
	return evalAtScalar(poly, id.scalar), nil
}

func evalAtScalar(poly Polynomial, x secp.Scalar) secp.Scalar {
	acc := secp.ScalarZero()
	for _, p := range slices.Backward(poly) {
		acc = secp.ScalarMul(acc, x)
		acc = secp.ScalarAdd(acc, p)
	}
	return acc
}

// LagrangeCoefficientAt returns the coefficient for reconstructing at x=0
// from an explicit set of epoch identifiers.
func LagrangeCoefficientAt(id Identifier, ids []Identifier) (secp.Scalar, error) {
	if err := id.Validate(); err != nil {
		return secp.Scalar{}, err
	}
	if len(ids) == 0 {
		return secp.Scalar{}, errors.New("shamir identifier set is empty")
	}

	num := secp.ScalarOne()
	den := secp.ScalarOne()
	seen := make(map[[secp.ScalarSize]byte]struct{}, len(ids))
	found := false
	for _, other := range ids {
		if err := other.Validate(); err != nil {
			return secp.Scalar{}, err
		}
		otherBytes := other.Bytes()
		var key [secp.ScalarSize]byte
		copy(key[:], otherBytes)
		clear(otherBytes)
		if _, ok := seen[key]; ok {
			return secp.Scalar{}, errors.New("duplicate Shamir identifier")
		}
		seen[key] = struct{}{}
		if other.Equal(id) {
			found = true
			continue
		}
		num = secp.ScalarMul(num, other.scalar)
		den = secp.ScalarMul(den, secp.ScalarSub(other.scalar, id.scalar))
	}
	if !found {
		return secp.Scalar{}, errors.New("target Shamir identifier is not in interpolation set")
	}
	inv, err := secp.ScalarInvert(den)
	if err != nil {
		return secp.Scalar{}, errors.New("non-invertible interpolation denominator")
	}
	return secp.ScalarMul(num, inv), nil
}
