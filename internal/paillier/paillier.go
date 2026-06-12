package paillier

import (
	"errors"
	"math/big"

	"github.com/islishude/tss/internal/secret"
)

// PublicKey contains Paillier public parameters and cached n^2.
type PublicKey struct {
	N        *big.Int `wire:"1,bigpos"`
	G        *big.Int `wire:"2,bigpos"`
	NSquared *big.Int `wire:"-"`
}

// WireType returns the canonical wire type identifier for PublicKey.
func (PublicKey) WireType() string { return publicKeyWireType }

// WireVersion returns the wire format version for PublicKey.
func (PublicKey) WireVersion() uint16 { return paillierWireVersion }

// AfterUnmarshalWire reconstructs the cached NSquared value after wire decoding.
func (pk *PublicKey) AfterUnmarshalWire() error {
	if pk.N != nil {
		pk.NSquared = new(big.Int).Mul(pk.N, pk.N)
	}
	return nil
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

// Clone returns a deep copy of the Paillier private key. The clone is
// independent of the original — mutating the clone does not affect the
// original. Clone is safe for use in test fixture caches where callers
// must receive isolated copies.
func (sk *PrivateKey) Clone() *PrivateKey {
	if sk == nil {
		return nil
	}
	return &PrivateKey{
		PublicKey: PublicKey{
			N:        new(big.Int).Set(sk.N),
			G:        new(big.Int).Set(sk.G),
			NSquared: new(big.Int).Set(sk.NSquared),
		},
		Lambda: sk.Lambda.Clone(),
		Mu:     sk.Mu.Clone(),
		P:      new(big.Int).Set(sk.P),
		Q:      new(big.Int).Set(sk.Q),
	}
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

// privateKeyWire is the wire DTO for PrivateKey.
type privateKeyWire struct {
	N      []byte `wire:"1,bytes"`
	G      []byte `wire:"2,bytes"`
	Lambda []byte `wire:"3,bytes"`
	Mu     []byte `wire:"4,bytes"`
	P      []byte `wire:"5,bytes"`
	Q      []byte `wire:"6,bytes"`
}

// WireType returns the canonical wire type identifier for privateKeyWire.
func (privateKeyWire) WireType() string { return privateKeyWireType }

// WireVersion returns the wire format version for privateKeyWire.
func (privateKeyWire) WireVersion() uint16 { return paillierWireVersion }
