package paillier

import (
	"errors"

	"github.com/islishude/tss"
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
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.FrameLimits{MaxTotalBytes: tss.DefaultMaxPaillierPublicKeyBytes}),
		wire.WithFieldLimits(wire.FieldLimits{
			"paillier_modulus_bits": maxBits,
		}),
	); err != nil {
		return err
	}
	// Validate is called automatically by wire.Unmarshal after AfterUnmarshalWire
	// (which reconstructs NSquared). No manual validation needed.
	*pk = decoded
	return nil
}

// MarshalBinary returns a deterministic TLV private-key record.
func (sk PrivateKey) MarshalBinary() ([]byte, error) {
	return wire.Marshal(sk, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
	}))
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
	if sk == nil {
		return errors.New("nil Paillier private key")
	}
	var decoded PrivateKey
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.FrameLimits{MaxTotalBytes: tss.DefaultMaxPaillierPrivateKeyBytes}),
		wire.WithFieldLimits(wire.FieldLimits{
			"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
		}),
	); err != nil {
		return err
	}
	*sk = decoded
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
