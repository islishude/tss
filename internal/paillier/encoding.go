package paillier

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

// MarshalBinary returns a deterministic TLV public-key record.
// wire.Marshal calls Validate via the Validator interface.
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return wire.Marshal(pk, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
	}))
}

// UnmarshalPublicKey decodes and rejects non-canonical public-key encodings.
// wire.Unmarshal calls Validate via the Validator interface.
func UnmarshalPublicKey(in []byte) (*PublicKey, error) {
	return UnmarshalPublicKeyWithMaxModulusBits(in, 0)
}

// UnmarshalPublicKeyWithMaxModulusBits decodes a public key and rejects an
// oversized modulus before reconstructing N² or running primality checks.
// The modulus bit-length check is enforced by wire.Unmarshal via the
// max_bits=paillier_modulus_bits wire tag on PublicKey.
func UnmarshalPublicKeyWithMaxModulusBits(in []byte, maxBits int) (*PublicKey, error) {
	if maxBits <= 0 {
		maxBits = tss.DefaultMaxPaillierModulusBits
	}
	var pk PublicKey
	if err := wire.Unmarshal(in, &pk, wire.WithFieldLimits(wire.FieldLimits{
		"paillier_modulus_bits": maxBits,
	})); err != nil {
		return nil, err
	}
	// Validate is called automatically by wire.Unmarshal after AfterUnmarshalWire
	// (which reconstructs NSquared). No manual validation needed.
	return &pk, nil
}

// MarshalBinary returns a deterministic TLV private-key record.
func (sk PrivateKey) MarshalBinary() ([]byte, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	n, err := encodePositiveInt(sk.N)
	if err != nil {
		return nil, err
	}
	g, err := encodePositiveInt(sk.G)
	if err != nil {
		return nil, err
	}
	lambda, err := encodePositiveInt(scalarToBig(sk.Lambda))
	if err != nil {
		return nil, err
	}
	mu, err := encodePositiveInt(scalarToBig(sk.Mu))
	if err != nil {
		return nil, err
	}
	p, err := encodePositiveInt(sk.P)
	if err != nil {
		return nil, err
	}
	q, err := encodePositiveInt(sk.Q)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(privateKeyWire{N: n, G: g, Lambda: lambda, Mu: mu, P: p, Q: q})
}

// UnmarshalPrivateKey decodes and rejects non-canonical private-key encodings.
func UnmarshalPrivateKey(in []byte) (*PrivateKey, error) {
	var w privateKeyWire
	if err := wire.Unmarshal(in, &w); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntBytes(w.N)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntBytes(w.G)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	lambdaBig, err := decodePositiveIntBytes(w.Lambda)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muBig, err := decodePositiveIntBytes(w.Mu)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	p, err := decodePositiveIntBytes(w.P)
	if err != nil {
		return nil, fmt.Errorf("invalid p: %w", err)
	}
	q, err := decodePositiveIntBytes(w.Q)
	if err != nil {
		return nil, fmt.Errorf("invalid q: %w", err)
	}
	nLen := (n.BitLen() + 7) / 8
	lambdaSec, err := secret.NewScalar(paillierct.FixedEncode(lambdaBig, nLen), nLen)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muSec, err := secret.NewScalar(paillierct.FixedEncode(muBig, nLen), nLen)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	sk := &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        g,
		},
		Lambda: lambdaSec,
		Mu:     muSec,
		P:      p,
		Q:      q,
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	return sk, nil
}

// encodePositiveInt returns the minimal big-endian encoding of a positive integer.
// It uses [big.Int.Bytes] which omits the leading zero byte — the output is
// always minimal.
func encodePositiveInt(x *big.Int) ([]byte, error) {
	if x == nil || x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x.Bytes(), nil
}

// decodePositiveIntBytes decodes a minimal big-endian encoding of a positive
// integer. It rejects leading zero bytes to enforce canonical encoding —
// callers must pair this with [encodePositiveInt] (which produces minimal
// output) or ensure their source produces minimal encodings. Non-minimal
// encodings (e.g. from legacy formats) must be normalized before calling
// this function.
func decodePositiveIntBytes(raw []byte) (*big.Int, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty integer")
	}
	if raw[0] == 0 {
		return nil, errors.New("non-minimal integer encoding")
	}
	x := new(big.Int).SetBytes(raw)
	if x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x, nil
}
