package tss

import (
	"errors"
	"fmt"
)

const (
	// DefaultMaxParties is the maximum number of participants across algorithms.
	DefaultMaxParties = 64
	// DefaultMaxThreshold is the maximum threshold value across algorithms.
	DefaultMaxThreshold = 64
	// DefaultMaxSigners is the maximum number of concurrent signers.
	DefaultMaxSigners = 64

	// DefaultMaxEnvelopeBytes is the maximum wire-encoded envelope size (1 MiB).
	DefaultMaxEnvelopeBytes = 1 << 20
	// DefaultMaxEnvelopePayloadBytes is the maximum payload inside an envelope (1 MiB).
	DefaultMaxEnvelopePayloadBytes = 1 << 20
	// DefaultMaxPayloadTypeBytes caps the payload type identifier length.
	DefaultMaxPayloadTypeBytes = 128
	// DefaultMaxProtocolNameBytes caps the protocol name length inside envelopes.
	DefaultMaxProtocolNameBytes = 64

	// DefaultMaxWireFields caps the field count inside a TLV message.
	DefaultMaxWireFields = 256
	// DefaultMaxWireFieldBytes caps a single TLV field value.
	DefaultMaxWireFieldBytes = 1 << 20
	// DefaultMaxWireRepeatedItems caps repeated items inside a wire field.
	DefaultMaxWireRepeatedItems = 128

	// DefaultMaxSerializedKeyShareBytes caps serialized KeyShare size (2 MiB).
	DefaultMaxSerializedKeyShareBytes = 2 << 20
	// DefaultMaxSerializedPresignBytes caps serialized Presign size (2 MiB).
	DefaultMaxSerializedPresignBytes = 2 << 20
	// DefaultMaxSerializedSignatureBytes caps serialized Signature size (64 KiB).
	DefaultMaxSerializedSignatureBytes = 64 << 10

	// DefaultMaxPointBytes caps curve point encoding size.
	DefaultMaxPointBytes = 65
	// DefaultMaxScalarBytes caps curve scalar encoding size.
	DefaultMaxScalarBytes = 32

	// DefaultMaxShamirDegree caps the polynomial degree in Shamir sharing.
	DefaultMaxShamirDegree = 64
	// DefaultMaxShamirShares caps the number of shares in interpolation.
	DefaultMaxShamirShares = 64

	// DefaultMinPaillierModulusBits is the minimum Paillier modulus size in production (3072 bits).
	DefaultMinPaillierModulusBits = 3072
	// DefaultMaxPaillierModulusBits caps the Paillier modulus size (8192 bits).
	DefaultMaxPaillierModulusBits = 8192
	// DefaultMaxPaillierPublicKeyBytes caps marshaled Paillier public key size.
	DefaultMaxPaillierPublicKeyBytes = 2048
	// DefaultMaxPaillierPrivateKeyBytes caps marshaled Paillier private key size.
	DefaultMaxPaillierPrivateKeyBytes = 4096
	// DefaultMaxPaillierCiphertextBytes caps a Paillier ciphertext (N^2 encoding).
	DefaultMaxPaillierCiphertextBytes = 2048
	// DefaultMaxPaillierProofBytes caps Paillier-related ZK proof size (256 KiB).
	DefaultMaxPaillierProofBytes = 256 << 10
	// DefaultMaxRingPedersenParamsBytes caps Ring-Pedersen parameter marshaling.
	DefaultMaxRingPedersenParamsBytes = 16384
	// DefaultMaxMTAResponseBytes caps an MtA response message size (512 KiB).
	DefaultMaxMTAResponseBytes = 512 << 10
	// DefaultMaxZKProofBytes caps any ZK proof input (512 KiB).
	DefaultMaxZKProofBytes = 512 << 10

	// MaxFROSTParties is the algorithm-specific party cap for FROST Ed25519.
	MaxFROSTParties = 64
	// MaxFROSTThreshold is the algorithm-specific threshold cap for FROST Ed25519.
	MaxFROSTThreshold = 64
	// MaxFROSTSigners is the algorithm-specific signer cap for FROST Ed25519.
	MaxFROSTSigners = 64

	// MaxCGGMPParties is the algorithm-specific party cap for CGGMP21 secp256k1.
	MaxCGGMPParties = 16
	// MaxCGGMPThreshold is the algorithm-specific threshold cap for CGGMP21 secp256k1.
	MaxCGGMPThreshold = 16
	// MaxCGGMPSigners is the algorithm-specific signer cap for CGGMP21 secp256k1.
	MaxCGGMPSigners = 16
)

// Limits defines finite caps for all security-sensitive parameters.
// Each algorithm package provides its own DefaultLimits() returning fail-closed
// production settings. Test code should use each package's TestLimits() or
// internal/testutil.TestLimits.
type Limits struct {
	MaxParties              int
	MaxThreshold            int
	MaxSigners              int
	MinProductionThreshold  int
	AllowOneOfOne           bool
	AllowOversizedSignerSet bool

	MaxEnvelopeBytes        int
	MaxEnvelopePayloadBytes int
	MaxPayloadTypeBytes     int
	MaxProtocolNameBytes    int

	MaxWireFields        int
	MaxWireFieldBytes    int
	MaxWireRepeatedItems int

	MaxSerializedKeyShareBytes  int
	MaxSerializedPresignBytes   int
	MaxSerializedSignatureBytes int

	MaxPointBytes  int
	MaxScalarBytes int

	MaxShamirDegree int
	MaxShamirShares int

	MaxPaillierModulusBits     int
	MinPaillierModulusBits     int
	MaxPaillierPublicKeyBytes  int
	MaxPaillierPrivateKeyBytes int
	MaxPaillierCiphertextBytes int
	MaxPaillierProofBytes      int
	MaxRingPedersenParamsBytes int
	MaxMTAResponseBytes        int
	MaxZKProofBytes            int
}

// DefaultLimits returns a conservative fail-closed Limits suitable as a fallback
// for callers that do not specify an algorithm. It rejects 1-of-1, oversized
// signer sets, and thresholds below 2. Callers that need relaxed limits for
// testing must use algorithm-specific TestLimits or internal/testutil.TestLimits.
func DefaultLimits() Limits {
	return Limits{
		MaxParties:              DefaultMaxParties,
		MaxThreshold:            DefaultMaxThreshold,
		MaxSigners:              DefaultMaxSigners,
		MinProductionThreshold:  2,
		AllowOneOfOne:           false,
		AllowOversizedSignerSet: false,

		MaxEnvelopeBytes:        DefaultMaxEnvelopeBytes,
		MaxEnvelopePayloadBytes: DefaultMaxEnvelopePayloadBytes,
		MaxPayloadTypeBytes:     DefaultMaxPayloadTypeBytes,
		MaxProtocolNameBytes:    DefaultMaxProtocolNameBytes,

		MaxWireFields:        DefaultMaxWireFields,
		MaxWireFieldBytes:    DefaultMaxWireFieldBytes,
		MaxWireRepeatedItems: DefaultMaxWireRepeatedItems,

		MaxSerializedKeyShareBytes:  DefaultMaxSerializedKeyShareBytes,
		MaxSerializedPresignBytes:   DefaultMaxSerializedPresignBytes,
		MaxSerializedSignatureBytes: DefaultMaxSerializedSignatureBytes,

		MaxPointBytes:  DefaultMaxPointBytes,
		MaxScalarBytes: DefaultMaxScalarBytes,

		MaxShamirDegree: DefaultMaxShamirDegree,
		MaxShamirShares: DefaultMaxShamirShares,

		MaxPaillierModulusBits:     DefaultMaxPaillierModulusBits,
		MinPaillierModulusBits:     DefaultMinPaillierModulusBits,
		MaxPaillierPublicKeyBytes:  DefaultMaxPaillierPublicKeyBytes,
		MaxPaillierPrivateKeyBytes: DefaultMaxPaillierPrivateKeyBytes,
		MaxPaillierCiphertextBytes: DefaultMaxPaillierCiphertextBytes,
		MaxPaillierProofBytes:      DefaultMaxPaillierProofBytes,
		MaxRingPedersenParamsBytes: DefaultMaxRingPedersenParamsBytes,
		MaxMTAResponseBytes:        DefaultMaxMTAResponseBytes,
		MaxZKProofBytes:            DefaultMaxZKProofBytes,
	}
}

// Validate checks that the Limits values are self-consistent.
func (l Limits) Validate() error {
	if l.MaxParties <= 0 {
		return errors.New("MaxParties must be positive")
	}
	if l.MaxThreshold <= 0 {
		return errors.New("MaxThreshold must be positive")
	}
	if l.MaxThreshold > l.MaxParties {
		return errors.New("MaxThreshold cannot exceed MaxParties")
	}
	if l.MaxSigners <= 0 {
		return errors.New("MaxSigners must be positive")
	}
	if l.MaxSigners > l.MaxParties {
		return errors.New("MaxSigners cannot exceed MaxParties")
	}
	if l.MinProductionThreshold < 0 {
		return errors.New("MinProductionThreshold must be non-negative")
	}
	if l.MinPaillierModulusBits <= 0 {
		return errors.New("MinPaillierModulusBits must be positive")
	}
	if l.MaxPaillierModulusBits < l.MinPaillierModulusBits {
		return fmt.Errorf("MaxPaillierModulusBits (%d) must be >= MinPaillierModulusBits (%d)",
			l.MaxPaillierModulusBits, l.MinPaillierModulusBits)
	}
	if l.MaxEnvelopeBytes <= 0 {
		return errors.New("MaxEnvelopeBytes must be positive")
	}
	if l.MaxWireFields <= 0 {
		return errors.New("MaxWireFields must be positive")
	}
	if l.MaxWireFieldBytes <= 0 {
		return errors.New("MaxWireFieldBytes must be positive")
	}
	return nil
}
