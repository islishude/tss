package paillier

import (
	"errors"
	"fmt"
	"math/big"
)

// RingPedersenParams are CGGMP Ring-Pedersen public parameters. N must match
// the party Paillier modulus and s,t must be non-degenerate elements of Z*_N.
// This type is re-exported here for the new proof system; the canonical
// definition and marshal/unmarshal remain in proofs.go for backward
// compatibility with ModulusProof and RingPedersenProof.
//
// NOTE: Eventually RingPedersenParams and its marshal/unmarshal should be
// moved here from proofs.go. For now, this file provides the commitment
// helpers that the new proofs (Πenc, Πaff-g, Πlog*) consume.

// RPCommit computes the Ring-Pedersen commitment: S^x * T^mu mod N.
// Both x and mu may be negative; negative exponents are handled via
// modular inverse.
func RPCommit(params RingPedersenParams, x, mu *big.Int) (*big.Int, error) {
	if err := validateRPParamsForCommit(params); err != nil {
		return nil, err
	}
	return MultiExpSignedMod(params.S, x, params.T, mu, params.N)
}

// RPCommitCT computes the Ring-Pedersen commitment using fixed-width
// constant-time exponentiation for secret witness and mask exponents.
func RPCommitCT(params RingPedersenParams, x, mu *big.Int, expLen int) (*big.Int, error) {
	if err := validateRPParamsForCommit(params); err != nil {
		return nil, err
	}
	if expLen <= 0 {
		return nil, errors.New("invalid RPCommitCT exponent length")
	}
	modLen := modulusBytes(params.N)
	r1, err := ExpSignedModCT(params.N, params.S, x, modLen, expLen)
	if err != nil {
		return nil, fmt.Errorf("RPCommitCT first term: %w", err)
	}
	r2, err := ExpSignedModCT(params.N, params.T, mu, modLen, expLen)
	if err != nil {
		return nil, fmt.Errorf("RPCommitCT second term: %w", err)
	}
	result := new(big.Int).Mul(r1, r2)
	result.Mod(result, params.N)
	return result, nil
}

// ExpSignedMod computes base^exp mod modulus, handling negative exponents
// via modular inverse of the base.
func ExpSignedMod(base, exp, modulus *big.Int) (*big.Int, error) {
	if base == nil || exp == nil || modulus == nil {
		return nil, errors.New("nil ExpSignedMod input")
	}
	if modulus.Sign() <= 0 {
		return nil, errors.New("invalid ExpSignedMod modulus")
	}

	e := new(big.Int).Set(exp)
	b := new(big.Int).Set(base)

	if e.Sign() < 0 {
		e.Neg(e)
		b.ModInverse(b, modulus)
		if b == nil {
			return nil, errors.New("base is not invertible modulo modulus for negative exponent")
		}
	}

	// For base ≡ 1 (mod modulus), Exp is trivial; avoid unnecessary work.
	result := new(big.Int).Exp(b, e, modulus)
	return result, nil
}

// MultiExpSignedMod computes base1^exp1 * base2^exp2 mod modulus, handling
// negative exponents via modular inverse.
func MultiExpSignedMod(base1, exp1, base2, exp2, modulus *big.Int) (*big.Int, error) {
	if base1 == nil || exp1 == nil || base2 == nil || exp2 == nil || modulus == nil {
		return nil, errors.New("nil MultiExpSignedMod input")
	}
	if modulus.Sign() <= 0 {
		return nil, errors.New("invalid MultiExpSignedMod modulus")
	}

	r1, err := ExpSignedMod(base1, exp1, modulus)
	if err != nil {
		return nil, fmt.Errorf("multi-exp first term: %w", err)
	}
	r2, err := ExpSignedMod(base2, exp2, modulus)
	if err != nil {
		return nil, fmt.Errorf("multi-exp second term: %w", err)
	}

	result := new(big.Int).Mul(r1, r2)
	result.Mod(result, modulus)
	return result, nil
}

// ExpSignedModCT computes base^exp mod modulus using constant-time
// exponentiation, handling negative exponents via modular inverse of the base.
// The modulus and exponent must have consistent fixed-width encodings.
func ExpSignedModCT(modulus, base, exp *big.Int, modLen, expLen int) (*big.Int, error) {
	if base == nil || exp == nil || modulus == nil {
		return nil, errors.New("nil ExpSignedModCT input")
	}
	if modulus.Sign() <= 0 {
		return nil, errors.New("invalid ExpSignedModCT modulus")
	}

	e := new(big.Int).Set(exp)
	b := new(big.Int).Set(base)

	forcedCT := false
	if e.Sign() < 0 {
		e.Neg(e)
		b.ModInverse(b, modulus)
		if b == nil {
			return nil, errors.New("base is not invertible modulo modulus for negative exponent")
		}
		// When the exponent is negative (e.g., secret scalar in RP commitment),
		// we still use constant-time ExpCT on the inverted base.
		forcedCT = true
	}

	if forcedCT || expLen > 0 {
		return expSecretMod(modulus, b, e, modLen, expLen)
	}
	return new(big.Int).Exp(b, e, modulus), nil
}

func validateRPParamsForCommit(params RingPedersenParams) error {
	if params.N == nil || params.S == nil || params.T == nil {
		return errors.New("nil Ring-Pedersen parameter")
	}
	if params.N.Sign() <= 0 || params.N.Bit(0) == 0 {
		return errors.New("invalid Ring-Pedersen modulus for commitment")
	}
	if !IsZNStar(params.S, params.N) {
		return errors.New("Ring-Pedersen S is not in Z*_N")
	}
	if !IsZNStar(params.T, params.N) {
		return errors.New("Ring-Pedersen T is not in Z*_N")
	}
	if params.S.Cmp(big.NewInt(1)) <= 0 || params.T.Cmp(big.NewInt(1)) <= 0 {
		return errors.New("degenerate Ring-Pedersen parameters")
	}
	return nil
}

// expSecretMod is a thin wrapper around paillierct.ExpCT used by both
// the old proofs (in proofs.go) and the new ring_pedersen.go helpers.
// It mirrors the function currently in proofs.go; do not duplicate it.
