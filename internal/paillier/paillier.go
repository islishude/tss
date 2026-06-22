package paillier

import (
	"errors"
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

// PublicKey contains Paillier public parameters and cached n^2.
type PublicKey struct {
	N        *big.Int `wire:"1,bigpos,max_bits=paillier_modulus_bits"`
	G        *big.Int `wire:"2,bigpos,max_bits=paillier_modulus_bits"`
	NSquared *big.Int `wire:"-"`
}

// WireType returns the canonical wire type identifier for PublicKey.
func (PublicKey) WireType() string { return publicKeyWireType }

// WireVersion returns the wire format version for PublicKey.
func (PublicKey) WireVersion() uint16 { return publicKeyWireVersion }

// AfterUnmarshalWire reconstructs the cached NSquared value after wire decoding.
func (pk *PublicKey) AfterUnmarshalWire() error {
	if pk.N != nil {
		pk.NSquared = new(big.Int).Mul(pk.N, pk.N)
	}
	return nil
}

// Clone returns a deep copy of PublicKey
func (pk *PublicKey) Clone() *PublicKey {
	if pk == nil {
		return nil
	}
	return &PublicKey{
		N:        tss.CloneBigInt(pk.N),
		G:        tss.CloneBigInt(pk.G),
		NSquared: tss.CloneBigInt(pk.NSquared),
	}
}

// PrivateKey contains Paillier secret factors and decryption exponents.
// All private factors and exponents use fixed-length secret.Scalar values to
// prevent accidental logging and long-lived variable-width representations.
type PrivateKey struct {
	PublicKey
	Lambda *secret.Scalar
	Mu     *secret.Scalar
	P      *secret.Scalar
	Q      *secret.Scalar
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
	pk := sk.PublicKey.Clone()
	var publicKey PublicKey
	if pk != nil {
		publicKey = *pk
	}
	return &PrivateKey{
		PublicKey: publicKey,
		Lambda:    sk.Lambda.Clone(),
		Mu:        sk.Mu.Clone(),
		P:         sk.P.Clone(),
		Q:         sk.Q.Clone(),
	}
}

// Destroy clears Paillier private exponents and factors in place.
func (sk *PrivateKey) Destroy() {
	if sk == nil {
		return
	}
	sk.Lambda.Destroy()
	sk.Mu.Destroy()
	sk.P.Destroy()
	sk.Q.Destroy()
}

const (
	publicKeyWireType    = "paillier.public-key"
	privateKeyType       = "paillier.private-key"
	publicKeyWireVersion = 1
	privateKeyVersion    = 1
)

// WireType returns the canonical wire type identifier for PrivateKey.
func (PrivateKey) WireType() string { return privateKeyType }

// WireVersion returns the wire format version for PrivateKey.
func (PrivateKey) WireVersion() uint16 { return privateKeyVersion }
