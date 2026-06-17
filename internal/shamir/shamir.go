package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/islishude/tss"
)

// Share is one Shamir evaluation point over a caller-supplied field order.
type Share struct {
	ID    tss.PartyID
	Value *big.Int
}

// RandomScalar returns a non-zero scalar modulo order.
func RandomScalar(reader io.Reader, order *big.Int) (*big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if order == nil || order.Sign() <= 0 {
		return nil, errors.New("invalid order")
	}
	for {
		x, err := rand.Int(reader, order)
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

// RandomPolynomial returns coefficients for a degree threshold-1 polynomial.
func RandomPolynomial(reader io.Reader, order *big.Int, threshold int, constant *big.Int) ([]*big.Int, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
	}
	// A threshold of k maps to a degree k-1 polynomial; coeffs[0] is the secret.
	coeffs := make([]*big.Int, threshold)
	if constant != nil {
		coeffs[0] = Normalize(constant, order)
	} else {
		x, err := RandomScalar(reader, order)
		if err != nil {
			return nil, err
		}
		coeffs[0] = x
	}
	for i := 1; i < threshold; i++ {
		x, err := RandomScalar(reader, order)
		if err != nil {
			return nil, err
		}
		coeffs[i] = x
	}
	return coeffs, nil
}

// Eval evaluates a polynomial at the participant identifier modulo order.
func Eval(coeffs []*big.Int, id tss.PartyID, order *big.Int) *big.Int {
	x := new(big.Int).SetUint64(uint64(id))
	acc := new(big.Int)
	// Horner evaluation keeps the code compact and avoids temporary powers.
	for _, coeff := range slices.Backward(coeffs) {
		acc.Mul(acc, x)
		acc.Add(acc, coeff)
		acc.Mod(acc, order)
	}
	return acc
}

// LagrangeCoefficient returns the coefficient for reconstructing at x=0.
func LagrangeCoefficient(id tss.PartyID, ids tss.PartySet, order *big.Int) (*big.Int, error) {
	if id == 0 {
		return nil, errors.New("party id 0 is reserved")
	}
	xi := new(big.Int).SetUint64(uint64(id))
	num := big.NewInt(1)
	den := big.NewInt(1)
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
		xj := new(big.Int).SetUint64(uint64(other))
		// Coefficients are evaluated at x=0 to reconstruct the polynomial constant.
		num.Mul(num, xj)
		num.Mod(num, order)

		diff := new(big.Int).Sub(xj, xi)
		diff.Mod(diff, order)
		den.Mul(den, diff)
		den.Mod(den, order)
	}
	if _, ok := seen[id]; !ok {
		return nil, fmt.Errorf("party id %d not in interpolation set", id)
	}
	inv := new(big.Int).ModInverse(den, order)
	if inv == nil {
		return nil, errors.New("non-invertible interpolation denominator")
	}
	out := new(big.Int).Mul(num, inv)
	out.Mod(out, order)
	return out, nil
}

// InterpolateConstant reconstructs the polynomial constant from shares.
func InterpolateConstant(shares []Share, order *big.Int) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares")
	}
	ids := make(tss.PartySet, len(shares))
	values := make(map[tss.PartyID]*big.Int, len(shares))
	for i, share := range shares {
		if share.Value == nil {
			return nil, fmt.Errorf("nil share for party %d", share.ID)
		}
		ids[i] = share.ID
		values[share.ID] = share.Value
	}
	acc := new(big.Int)
	for _, id := range ids {
		lambda, err := LagrangeCoefficient(id, ids, order)
		if err != nil {
			return nil, err
		}
		term := new(big.Int).Mul(values[id], lambda)
		acc.Add(acc, term)
		acc.Mod(acc, order)
	}
	return acc, nil
}

// Normalize reduces x into [0, order).
func Normalize(x, order *big.Int) *big.Int {
	out := new(big.Int).Mod(new(big.Int).Set(x), order)
	if out.Sign() < 0 {
		out.Add(out, order)
	}
	return out
}

// Add returns a+b modulo order.
func Add(a, b, order *big.Int) *big.Int {
	out := new(big.Int).Add(a, b)
	out.Mod(out, order)
	return out
}

// Sub returns a-b modulo order.
func Sub(a, b, order *big.Int) *big.Int {
	out := new(big.Int).Sub(a, b)
	out.Mod(out, order)
	return out
}

// Mul returns a*b modulo order.
func Mul(a, b, order *big.Int) *big.Int {
	out := new(big.Int).Mul(a, b)
	out.Mod(out, order)
	return out
}
