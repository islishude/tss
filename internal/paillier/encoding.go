package paillier

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

// MarshalBinary returns a deterministic TLV public-key record.
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	n, err := encodePositiveInt(pk.N)
	if err != nil {
		return nil, err
	}
	g, err := encodePositiveInt(pk.G)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(paillierWireVersion, publicKeyWireType, []wire.Field{
		{Tag: publicKeyFieldN, Value: n},
		{Tag: publicKeyFieldG, Value: g},
	})
}

// UnmarshalPublicKey decodes and rejects non-canonical public-key encodings.
func UnmarshalPublicKey(in []byte) (*PublicKey, error) {
	version, fields, err := wire.Unmarshal(in, publicKeyWireType)
	if err != nil {
		return nil, err
	}
	if version != paillierWireVersion {
		return nil, fmt.Errorf("unexpected Paillier public-key version %d", version)
	}
	if err := requireExactKeyTags(fields, publicKeyFieldN, publicKeyFieldG); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntField(fields, publicKeyFieldN)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntField(fields, publicKeyFieldG)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	pk := &PublicKey{
		N:        n,
		NSquared: new(big.Int).Mul(n, n),
		G:        g,
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	return pk, nil
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
	return wire.Marshal(paillierWireVersion, privateKeyWireType, []wire.Field{
		{Tag: privateKeyFieldN, Value: n},
		{Tag: privateKeyFieldG, Value: g},
		{Tag: privateKeyFieldLambda, Value: lambda},
		{Tag: privateKeyFieldMu, Value: mu},
		{Tag: privateKeyFieldP, Value: p},
		{Tag: privateKeyFieldQ, Value: q},
	})
}

// UnmarshalPrivateKey decodes and rejects non-canonical private-key encodings.
func UnmarshalPrivateKey(in []byte) (*PrivateKey, error) {
	version, fields, err := wire.Unmarshal(in, privateKeyWireType)
	if err != nil {
		return nil, err
	}
	if version != paillierWireVersion {
		return nil, fmt.Errorf("unexpected Paillier private-key version %d", version)
	}
	if err := requireExactKeyTags(fields, privateKeyFieldN, privateKeyFieldG, privateKeyFieldLambda, privateKeyFieldMu, privateKeyFieldP, privateKeyFieldQ); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntField(fields, privateKeyFieldN)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntField(fields, privateKeyFieldG)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	lambdaBig, err := decodePositiveIntField(fields, privateKeyFieldLambda)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muBig, err := decodePositiveIntField(fields, privateKeyFieldMu)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	p, err := decodePositiveIntField(fields, privateKeyFieldP)
	if err != nil {
		return nil, fmt.Errorf("invalid p: %w", err)
	}
	q, err := decodePositiveIntField(fields, privateKeyFieldQ)
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

func requireExactKeyTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("got %d fields, want %d", len(fields), len(tags))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected field tag %d at index %d", fields[i].Tag, i)
		}
	}
	return nil
}

func encodePositiveInt(x *big.Int) ([]byte, error) {
	if x == nil || x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x.Bytes(), nil
}

func decodePositiveIntField(fields []wire.Field, tag uint16) (*big.Int, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
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
