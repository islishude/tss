package paillier

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss/internal/secret"
)

// Validate checks public key structural invariants: modulus is odd, composite,
// safe-prime pattern (≡ 1 mod 4, not divisible by 3), NSquared is N², and
// generator is n+1. Validate does NOT enforce a minimum modulus size — callers
// that need a security-parameter bit-length check should use ValidateBits or
// SecurityParams.CheckPaillierModulus.
func (pk *PublicKey) Validate() error {
	if pk == nil {
		return errors.New("nil PublicKey")
	}
	if pk.N == nil || pk.N.Sign() <= 0 {
		return errors.New("invalid modulus")
	}
	if pk.N.Bit(0) == 0 {
		return errors.New("paillier modulus must be odd")
	}
	if pk.N.ProbablyPrime(64) {
		return errors.New("paillier modulus must be composite")
	}
	// Safe-prime structural checks: for p = 2p'+1, q = 2q'+1, we have
	// N ≡ 1 (mod 4) and N mod 3 ≠ 0 (excludes p=3 or q=3 which makes
	// (p-1)/2 = 1 not prime).
	four := big.NewInt(4)
	three := big.NewInt(3)
	if new(big.Int).Mod(pk.N, four).Cmp(big.NewInt(1)) != 0 {
		return errors.New("paillier modulus must be ≡ 1 mod 4 for safe primes")
	}
	if new(big.Int).Mod(pk.N, three).Sign() == 0 {
		return errors.New("paillier modulus must not be divisible by 3")
	}
	if pk.NSquared == nil || pk.NSquared.Cmp(new(big.Int).Mul(pk.N, pk.N)) != 0 {
		return errors.New("invalid n squared")
	}
	if pk.G == nil || pk.G.Sign() <= 0 || pk.G.Cmp(pk.NSquared) >= 0 {
		return errors.New("invalid generator")
	}
	if pk.G.Cmp(new(big.Int).Add(pk.N, big.NewInt(1))) != 0 {
		return errors.New("paillier generator must be n+1")
	}
	return nil
}

// ValidateBits checks public key structure against an explicit minimum size.
func (pk *PublicKey) ValidateBits(minBits int) error {
	if err := pk.Validate(); err != nil {
		return err
	}
	if minBits > 0 && pk.N.BitLen() < minBits {
		return fmt.Errorf("paillier modulus has %d bits, need at least %d", pk.N.BitLen(), minBits)
	}
	return nil
}

// Validate checks both public Paillier parameters and private CRT material.
func (sk PrivateKey) Validate() error {
	if err := sk.PublicKey.Validate(); err != nil {
		return err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return errors.New("invalid secret scalar")
	}
	nLen := (sk.N.BitLen() + 7) / 8
	factorLen := (nLen + 1) / 2
	if sk.Lambda.FixedLen() != nLen || sk.Mu.FixedLen() != nLen {
		return errors.New("invalid secret scalar width")
	}
	if sk.P == nil || sk.P.FixedLen() != factorLen {
		return errors.New("invalid p")
	}
	if sk.Q == nil || sk.Q.FixedLen() != factorLen {
		return errors.New("invalid q")
	}
	p := scalarToBig(sk.P)
	defer secret.ClearBigInt(p)
	q := scalarToBig(sk.Q)
	defer secret.ClearBigInt(q)
	if p.Sign() <= 0 {
		return errors.New("invalid p")
	}
	if q.Sign() <= 0 {
		return errors.New("invalid q")
	}
	if p.Cmp(q) == 0 {
		return errors.New("paillier factors must differ")
	}
	if new(big.Int).Mul(p, q).Cmp(sk.N) != 0 {
		return errors.New("paillier factors do not multiply to modulus")
	}
	if !p.ProbablyPrime(64) || !q.ProbablyPrime(64) {
		return errors.New("paillier factors must be prime")
	}
	lambdaBig := scalarToBig(sk.Lambda)
	defer secret.ClearBigInt(lambdaBig)
	wantLambda := lcm(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	defer secret.ClearBigInt(wantLambda)
	if lambdaBig.Cmp(wantLambda) != 0 {
		return errors.New("invalid paillier lambda")
	}
	// For the enforced g=n+1 variant, L(g^lambda mod n^2) = lambda mod n.
	// This avoids variable-time modular exponentiation with secret lambda.
	wantMu := new(big.Int).ModInverse(lambdaBig, sk.N)
	defer secret.ClearBigInt(wantMu)
	muBig := scalarToBig(sk.Mu)
	defer secret.ClearBigInt(muBig)
	if wantMu == nil || muBig.Cmp(wantMu) != 0 {
		return errors.New("invalid paillier mu")
	}
	return nil
}

// scalarToBig converts a fixed-length secret.Scalar to a *big.Int.
//
// This crosses the secret.Scalar abstraction boundary: the returned *big.Int
// uses variable-length encoding and is not constant-time for comparison.
// Callers MUST use the result only for non-secret-exponent operations such as
// structural validation (checking λ = lcm(p-1, q-1)) and encoding. Never use
// the result in exponentiation or any operation where timing leaks matter.
//
// This is unexported; callers outside the paillier package must use the
// constant-time paths provided by paillierct.
func scalarToBig(s *secret.Scalar) *big.Int {
	if s == nil {
		return nil
	}
	fixed := s.FixedBytes()
	defer clear(fixed)
	return new(big.Int).SetBytes(fixed)
}
