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

var (
	_ wire.ValueMarshaler   = (*PrivateKey)(nil)
	_ wire.ValueUnmarshaler = (*PrivateKey)(nil)
)

// MarshalBinary returns a deterministic TLV public-key record.
// wire.Marshal calls Validate via the Validator interface.
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return wire.Marshal(pk, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
	}))
}

// UnmarshalPublicKeyWithMaxModulusBits decodes a public key and rejects an
// oversized modulus before reconstructing N² or running primality checks.
// The modulus bit-length check is enforced by wire.Unmarshal via the
// max_bits=paillier_modulus_bits wire tag on PublicKey.
func UnmarshalPublicKeyWithMaxModulusBits(in []byte, maxBits int) (*PublicKey, error) {
	pk := new(PublicKey)
	if err := pk.UnmarshalBinaryWithMaxModulusBits(in, maxBits); err != nil {
		return nil, err
	}
	return pk, nil
}

// UnmarshalBinary decodes and rejects non-canonical public-key encodings.
func (pk *PublicKey) UnmarshalBinary(in []byte) error {
	return pk.UnmarshalBinaryWithMaxModulusBits(in, 0)
}

// UnmarshalBinaryWithMaxModulusBits decodes a public key and rejects an
// oversized modulus before reconstructing derived fields.
func (pk *PublicKey) UnmarshalBinaryWithMaxModulusBits(in []byte, maxBits int) error {
	if maxBits <= 0 {
		maxBits = tss.DefaultMaxPaillierModulusBits
	}
	var decoded PublicKey
	if err := wire.Unmarshal(in, &decoded, wire.WithFieldLimits(wire.FieldLimits{
		"paillier_modulus_bits": maxBits,
	})); err != nil {
		return err
	}
	// Validate is called automatically by wire.Unmarshal after AfterUnmarshalWire
	// (which reconstructs NSquared). No manual validation needed.
	*pk = decoded
	return nil
}

// MarshalBinary returns a deterministic TLV private-key record.
func (sk PrivateKey) MarshalBinary() ([]byte, error) {
	return wire.Marshal(sk)
}

// MarshalWireMessage encodes PrivateKey as a canonical TLV message.
func (sk PrivateKey) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
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
	lambda, err := encodePositiveSecretScalar(sk.Lambda)
	if err != nil {
		return nil, err
	}
	defer clear(lambda)
	mu, err := encodePositiveSecretScalar(sk.Mu)
	if err != nil {
		return nil, err
	}
	defer clear(mu)
	p, err := encodePositiveSecretScalar(sk.P)
	if err != nil {
		return nil, err
	}
	defer clear(p)
	q, err := encodePositiveSecretScalar(sk.Q)
	if err != nil {
		return nil, err
	}
	defer clear(q)
	return wire.MarshalMessageBody(sk, []wire.Field{
		{Tag: 1, Value: n},
		{Tag: 2, Value: g},
		{Tag: 3, Value: lambda},
		{Tag: 4, Value: mu},
		{Tag: 5, Value: p},
		{Tag: 6, Value: q},
	})
}

// MarshalWireValue returns the canonical private-key message encoding for use
// as an opaque custom field in a containing wire message.
func (sk *PrivateKey) MarshalWireValue() ([]byte, error) {
	if sk == nil {
		return nil, errors.New("nil Paillier private key")
	}
	return sk.MarshalBinary()
}

// UnmarshalBinary decodes and rejects non-canonical private-key encodings.
func (sk *PrivateKey) UnmarshalBinary(in []byte) error {
	return sk.UnmarshalWireMessage(in)
}

// UnmarshalWireMessage decodes PrivateKey from a canonical TLV message.
func (sk *PrivateKey) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if sk == nil {
		return errors.New("nil Paillier private key")
	}
	fields, err := wire.UnmarshalMessageBody(in, sk, opts...)
	if err != nil {
		return err
	}
	if err := requirePrivateKeyTags(fields); err != nil {
		return err
	}
	n, err := decodePositiveIntBytes(fields[0].Value)
	if err != nil {
		return fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntBytes(fields[1].Value)
	if err != nil {
		return fmt.Errorf("invalid public generator: %w", err)
	}
	lambdaBig, err := decodePositiveIntBytes(fields[2].Value)
	if err != nil {
		return fmt.Errorf("invalid lambda: %w", err)
	}
	defer secret.ClearBigInt(lambdaBig)
	muBig, err := decodePositiveIntBytes(fields[3].Value)
	if err != nil {
		return fmt.Errorf("invalid mu: %w", err)
	}
	defer secret.ClearBigInt(muBig)
	p, err := decodePositiveIntBytes(fields[4].Value)
	if err != nil {
		return fmt.Errorf("invalid p: %w", err)
	}
	defer secret.ClearBigInt(p)
	q, err := decodePositiveIntBytes(fields[5].Value)
	if err != nil {
		return fmt.Errorf("invalid q: %w", err)
	}
	defer secret.ClearBigInt(q)
	nLen := (n.BitLen() + 7) / 8
	factorLen := (nLen + 1) / 2
	lambdaSec, err := secret.NewScalar(paillierct.FixedEncode(lambdaBig, nLen), nLen)
	if err != nil {
		return fmt.Errorf("invalid lambda: %w", err)
	}
	muSec, err := secret.NewScalar(paillierct.FixedEncode(muBig, nLen), nLen)
	if err != nil {
		lambdaSec.Destroy()
		return fmt.Errorf("invalid mu: %w", err)
	}
	pSec, err := secret.NewScalar(paillierct.FixedEncode(p, factorLen), factorLen)
	if err != nil {
		lambdaSec.Destroy()
		muSec.Destroy()
		return fmt.Errorf("invalid p: %w", err)
	}
	qSec, err := secret.NewScalar(paillierct.FixedEncode(q, factorLen), factorLen)
	if err != nil {
		lambdaSec.Destroy()
		muSec.Destroy()
		pSec.Destroy()
		return fmt.Errorf("invalid q: %w", err)
	}
	decoded := PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        g,
		},
		Lambda: lambdaSec,
		Mu:     muSec,
		P:      pSec,
		Q:      qSec,
	}
	if err := decoded.Validate(); err != nil {
		decoded.Destroy()
		return err
	}
	*sk = decoded
	return nil
}

func requirePrivateKeyTags(fields []wire.Field) error {
	if len(fields) != 6 {
		return fmt.Errorf("paillier private key field count %d != 6", len(fields))
	}
	for i, tag := range []uint16{1, 2, 3, 4, 5, 6} {
		if fields[i].Tag != tag {
			return fmt.Errorf("paillier private key field tag %d at index %d, want %d", fields[i].Tag, i, tag)
		}
	}
	return nil
}

// UnmarshalWireValue decodes a canonical private-key message from an opaque
// custom field in a containing wire message.
func (sk *PrivateKey) UnmarshalWireValue(in []byte) error {
	if sk == nil {
		return errors.New("nil Paillier private key")
	}
	return sk.UnmarshalBinary(in)
}

func encodePositiveSecretScalar(x *secret.Scalar) ([]byte, error) {
	if x == nil {
		return nil, errors.New("integer must be positive")
	}
	fixed := x.FixedBytes()
	defer clear(fixed)
	first := 0
	for first < len(fixed) && fixed[first] == 0 {
		first++
	}
	if first == len(fixed) {
		return nil, errors.New("integer must be positive")
	}
	out := make([]byte, len(fixed)-first)
	copy(out, fixed[first:])
	return out, nil
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
