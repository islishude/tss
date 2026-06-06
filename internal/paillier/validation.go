package paillier

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss/internal/secret"
)

// Validate checks the public key against the package minimum modulus size.
func (pk PublicKey) Validate() error {
	return pk.ValidateBits(minModulusBits)
}

// ValidateBits checks public key structure against an explicit minimum size.
func (pk PublicKey) ValidateBits(minBits int) error {
	if pk.N == nil || pk.N.Sign() <= 0 {
		return errors.New("invalid modulus")
	}
	if pk.N.Bit(0) == 0 {
		return errors.New("paillier modulus must be odd")
	}
	if minBits > 0 && pk.N.BitLen() < minBits {
		return fmt.Errorf("paillier modulus has %d bits, need at least %d", pk.N.BitLen(), minBits)
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

// Validate checks both public Paillier parameters and private CRT material.
func (sk PrivateKey) Validate() error {
	if err := sk.PublicKey.Validate(); err != nil {
		return err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return errors.New("invalid secret scalar")
	}
	for name, value := range map[string]*big.Int{
		"p": sk.P,
		"q": sk.Q,
	} {
		if value == nil || value.Sign() <= 0 {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if sk.P.Cmp(sk.Q) == 0 {
		return errors.New("paillier factors must differ")
	}
	if new(big.Int).Mul(sk.P, sk.Q).Cmp(sk.N) != 0 {
		return errors.New("paillier factors do not multiply to modulus")
	}
	if !sk.P.ProbablyPrime(64) || !sk.Q.ProbablyPrime(64) {
		return errors.New("paillier factors must be prime")
	}
	lambdaBig := scalarToBig(sk.Lambda)
	wantLambda := lcm(new(big.Int).Sub(sk.P, big.NewInt(1)), new(big.Int).Sub(sk.Q, big.NewInt(1)))
	if lambdaBig.Cmp(wantLambda) != 0 {
		return errors.New("invalid paillier lambda")
	}
	// For the enforced g=n+1 variant, L(g^lambda mod n^2) = lambda mod n.
	// This avoids variable-time modular exponentiation with secret lambda.
	wantMu := new(big.Int).ModInverse(lambdaBig, sk.N)
	if wantMu == nil || scalarToBig(sk.Mu).Cmp(wantMu) != 0 {
		return errors.New("invalid paillier mu")
	}
	return nil
}

// scalarToBig converts a fixed-length secret.Scalar to a *big.Int.
// This is unexported; callers outside the paillier package must use
// the constant-time paths provided by paillierct.
func scalarToBig(s *secret.Scalar) *big.Int {
	if s == nil {
		return nil
	}
	return new(big.Int).SetBytes(s.FixedBytes())
}
