package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	pai "github.com/islishude/tss/internal/paillier"
)

// IsZNStar reports whether x is a member of Z*_N (1 <= x < N and gcd(x, N) = 1).
func IsZNStar(x, n *big.Int) bool {
	if x == nil || n == nil {
		return false
	}
	if x.Sign() <= 0 || x.Cmp(n) >= 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, x, n).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return true
}

// IsZN2Star reports whether x is a member of Z*_{N^2}.
func IsZN2Star(x, n *big.Int) bool {
	if x == nil || n == nil {
		return false
	}
	n2 := new(big.Int).Mul(n, n)
	if x.Sign() <= 0 || x.Cmp(n2) >= 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, x, n2).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return true
}

// RequireZNStar returns x if x ∈ Z*_N, otherwise an error.
func RequireZNStar(x, n *big.Int) (*big.Int, error) {
	if !IsZNStar(x, n) {
		return nil, errors.New("value is not in Z*_N")
	}
	return x, nil
}

// RequireZN2Star returns x if x ∈ Z*_{N^2}, otherwise an error.
func RequireZN2Star(x, n *big.Int) (*big.Int, error) {
	if !IsZN2Star(x, n) {
		return nil, errors.New("value is not in Z*_N^2")
	}
	return x, nil
}

// Enc is a checked Paillier encryption of m under public key pk.
// Returns (ciphertext, randomness).
func Enc(pk *pai.PublicKey, rng io.Reader, m *big.Int) (*big.Int, *big.Int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if pk == nil {
		return nil, nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, nil, err
	}
	if m == nil {
		return nil, nil, errors.New("nil message")
	}
	return pk.Encrypt(rng, m)
}

// EncRandom is a checked Paillier encryption with caller-provided randomness.
func EncRandom(pk *pai.PublicKey, m, rho *big.Int) (*big.Int, error) {
	if pk == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if m == nil || rho == nil {
		return nil, errors.New("nil encryption input")
	}
	if !IsZNStar(rho, pk.N) {
		return nil, errors.New("randomness is not in Z*_N")
	}
	return pk.EncryptWithRandomness(m, rho)
}

// OAdd homomorphically adds two Paillier ciphertexts: (a ⊕ b) mod N^2.
func OAdd(pk *pai.PublicKey, a, b *big.Int) (*big.Int, error) {
	if pk == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	_, err := RequireZN2Star(a, pk.N)
	if err != nil {
		return nil, err
	}
	_, err = RequireZN2Star(b, pk.N)
	if err != nil {
		return nil, err
	}
	c := new(big.Int).Mul(a, b)
	c.Mod(c, pk.NSquared)
	return c, nil
}

// OMul homomorphically multiplies a Paillier ciphertext by a scalar: k ⊙ c mod N^2.
// A negative scalar is handled via modular inverse of the ciphertext.
func OMul(pk *pai.PublicKey, k, c *big.Int) (*big.Int, error) {
	if pk == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	_, err := RequireZN2Star(c, pk.N)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, errors.New("nil scalar")
	}

	exp := new(big.Int).Set(k)
	base := new(big.Int).Set(c)

	// Handle negative exponent: c^{-k} = (c^{-1})^k mod N^2
	if exp.Sign() < 0 {
		exp.Neg(exp)
		base.ModInverse(base, pk.NSquared)
		if base == nil {
			return nil, errors.New("ciphertext is not invertible modulo N^2")
		}
	}

	result := new(big.Int).Exp(base, exp, pk.NSquared)
	return result, nil
}

// OMulCT homomorphically multiplies a Paillier ciphertext by a secret scalar
// using fixed-width constant-time exponentiation. It delegates the sign-handling
// and constant-time exponentiation to ExpSignedModCT.
func OMulCT(pk *pai.PublicKey, k, c *big.Int, expLen int) (*big.Int, error) {
	if pk == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if _, err := RequireZN2Star(c, pk.N); err != nil {
		return nil, err
	}
	if k == nil {
		return nil, errors.New("nil scalar")
	}
	if expLen <= 0 {
		return nil, errors.New("invalid OMulCT exponent length")
	}

	nSquaredLen := 2 * modulusBytes(pk.N)
	return ExpSignedModCT(pk.NSquared, c, k, nSquaredLen, expLen)
}
