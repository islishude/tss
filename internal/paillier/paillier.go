package paillier

import (
	"errors"
	"math/big"

	"github.com/islishude/tss/internal/secret"
)

// DefaultMinModulusBits is the minimum modulus size accepted outside tests.
// 3072 bits provides ~128-bit classical security matching secp256k1 (NIST SP 800-57).
const DefaultMinModulusBits = 3072

var minModulusBits = DefaultMinModulusBits

// PublicKey contains Paillier public parameters and cached n^2.
type PublicKey struct {
	N        *big.Int
	NSquared *big.Int
	G        *big.Int
}

// PrivateKey contains Paillier secret factors and decryption exponents.
// Lambda and Mu use fixed-length secret.Scalar to prevent accidental logging,
// variable-length encoding, and non-constant-time conversion of secret material.
type PrivateKey struct {
	PublicKey
	Lambda *secret.Scalar
	Mu     *secret.Scalar
	P      *big.Int
	Q      *big.Int
}

// MarshalJSON rejects default JSON encoding of Paillier private keys.
func (sk PrivateKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("paillier private key contains secret material; use MarshalBinary")
}

// Destroy clears Paillier private exponents and factors in place.
func (sk *PrivateKey) Destroy() {
	if sk == nil {
		return
	}
	sk.Lambda.Destroy()
	sk.Mu.Destroy()
	secret.ClearBigInt(sk.P)
	secret.ClearBigInt(sk.Q)
}

const paillierWireVersion = 1

const (
	publicKeyWireType  = "paillier.public-key"
	privateKeyWireType = "paillier.private-key"
)

const (
	publicKeyFieldN uint16 = iota + 1
	publicKeyFieldG
)

const (
	privateKeyFieldN uint16 = iota + 1
	privateKeyFieldG
	privateKeyFieldLambda
	privateKeyFieldMu
	privateKeyFieldP
	privateKeyFieldQ
)

// SetMinimumModulusBitsForTesting overrides validation policy for tests.
func SetMinimumModulusBitsForTesting(bits int) func() {
	old := minModulusBits
	minModulusBits = bits
	return func() { minModulusBits = old }
}
