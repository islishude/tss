package tss

import "fmt"

const (
	// DefaultMaxParties is the maximum number of participants across algorithms.
	DefaultMaxParties = 64
	// DefaultMaxThreshold is the maximum threshold value across algorithms.
	DefaultMaxThreshold = 64
	// DefaultMaxSigners is the maximum number of concurrent signers.
	DefaultMaxSigners = 64
)

const (
	// DefaultMaxWireFields caps the field count inside a TLV message.
	DefaultMaxWireFields = 256
	// DefaultMaxWireFieldBytes caps a single TLV field value.
	DefaultMaxWireFieldBytes = 1 << 20
)

const (
	// DefaultMaxEnvelopeBytes is the maximum wire-encoded envelope size (1 MiB).
	DefaultMaxEnvelopeBytes = 1 << 20
	// DefaultMaxEnvelopePayloadBytes is the maximum payload inside an envelope (1 MiB).
	DefaultMaxEnvelopePayloadBytes = 1 << 20
	// DefaultMaxPayloadTypeBytes caps the payload type identifier length.
	DefaultMaxPayloadTypeBytes = 128
	// DefaultMaxProtocolNameBytes caps the protocol name length inside envelopes.
	DefaultMaxProtocolNameBytes = 64
	// DefaultMaxEnvelopeSignatureBytes caps a portable sender signature.
	DefaultMaxEnvelopeSignatureBytes = 4096
)

const (
	// DefaultMaxBlameEvidenceBytes caps the total encoded blame evidence size (1 MiB).
	DefaultMaxBlameEvidenceBytes = 1 << 20
	// DefaultMaxEvidenceReasonBytes caps the reason string length in blame evidence.
	DefaultMaxEvidenceReasonBytes = 256
	// DefaultMaxEvidenceFieldCount caps the number of public input fields in blame evidence.
	DefaultMaxEvidenceFieldCount = 64
	// DefaultMaxEvidenceFieldKeyBytes caps a single evidence field key length.
	DefaultMaxEvidenceFieldKeyBytes = 128
	// DefaultMaxEvidenceFieldValueBytes caps a single evidence field value length.
	DefaultMaxEvidenceFieldValueBytes = 1 << 20
)

const (
	// DefaultMaxSerializedKeyShareBytes caps serialized KeyShare size (2 MiB).
	DefaultMaxSerializedKeyShareBytes = 2 << 20
	// DefaultMaxSerializedPresignBytes caps serialized Presign size (2 MiB).
	DefaultMaxSerializedPresignBytes = 2 << 20
	// DefaultMaxSerializedResharePlanBytes caps serialized public reshare plans (1 MiB).
	DefaultMaxSerializedResharePlanBytes = 1 << 20
	// DefaultMaxSerializedTrustedDealerPlanBytes caps serialized trusted-dealer import plans (1 MiB).
	DefaultMaxSerializedTrustedDealerPlanBytes = 1 << 20
	// DefaultMaxSerializedTrustedDealerContributionBytes caps one serialized secret contribution (64 KiB).
	DefaultMaxSerializedTrustedDealerContributionBytes = 64 << 10
)

const (
	// DefaultMaxPointBytes caps curve point encoding size.
	DefaultMaxPointBytes = 65
	// DefaultMaxScalarBytes caps curve scalar encoding size.
	DefaultMaxScalarBytes = 32
)

const (
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
)

// ThresholdLimits defines finite caps for threshold protocol parameters.
type ThresholdLimits struct {
	MaxParties              int
	MaxThreshold            int
	MaxSigners              int
	MinProductionThreshold  int
	AllowOneOfOne           bool
	AllowOversizedSignerSet bool
}

// ValidateThreshold checks that threshold and party count comply with the
// configured production minimum and AllowOneOfOne policy.
func (l ThresholdLimits) ValidateThreshold(threshold, nParties int) error {
	if threshold < l.MinProductionThreshold {
		if !l.AllowOneOfOne || threshold != 1 || nParties != 1 {
			return fmt.Errorf("threshold %d is below production minimum %d", threshold, l.MinProductionThreshold)
		}
	}
	return nil
}

// TLVLimits caps wire-level TLV field counts and per-field sizes.
type TLVLimits struct {
	MaxFields     int
	MaxFieldBytes int
}

// EnvelopeLimits caps envelope encoding and metadata sizes.
type EnvelopeLimits struct {
	MaxBytes             int
	MaxPayloadBytes      int
	MaxPayloadTypeBytes  int
	MaxProtocolNameBytes int
	MaxSignatureBytes    int
	TLV                  TLVLimits
}

// EvidenceLimits caps blame evidence encoding and field sizes.
type EvidenceLimits struct {
	MaxBytes            int
	MaxReasonBytes      int
	MaxFieldCount       int
	MaxFieldKeyBytes    int
	MaxFieldValueBytes  int
	MaxPayloadTypeBytes int
	TLV                 TLVLimits
}
