package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// CGGMP21 secp256k1 algorithm-specific limits.
const (
	maxCGGMPParties   = 16
	maxCGGMPThreshold = 16
	maxCGGMPSigners   = 16

	maxSignPrepProofBytes      = 512 << 10
	maxSignVerifyShareBytes    = 65*2 + maxSignPrepProofBytes + 8
	maxSignVerifySharesBytes   = maxCGGMPSigners * maxSignVerifyShareBytes
	maxSignPartialPayloadBytes = 32*6 + maxSignPrepProofBytes + 256
)

// StateLimits caps serialized CGGMP21 key material.
type StateLimits struct {
	MaxSerializedKeyShareBytes    int
	MaxSerializedPresignBytes     int
	MaxSerializedResharePlanBytes int
	MaxSerializedSignAttemptBytes int
}

// PayloadLimits caps CGGMP21 payload sizes.
type PayloadLimits struct {
	MaxMessageBytes int
}

// CurveLimits caps secp256k1 curve point and scalar encoding sizes.
type CurveLimits struct {
	MaxPointBytes  int
	MaxScalarBytes int
}

// PaillierLimits caps Paillier key, ciphertext, and proof sizes.
type PaillierLimits struct {
	MaxModulusBits       int
	MaxPublicKeyBytes    int
	MaxPrivateKeyBytes   int
	MaxCiphertextBytes   int
	MaxProofBytes        int
	MaxRingPedersenBytes int
	MaxMTAResponseBytes  int
}

// ZKLimits caps ZK proof payload sizes.
type ZKLimits struct {
	MaxProofBytes int
}

// SignPrepLimits caps CGGMP21 signprep and partial signature sizes.
type SignPrepLimits struct {
	MaxProofBytes              int
	MaxVerifyShareBytes        int
	MaxVerifySharesBytes       int
	MaxSignPartialPayloadBytes int
}

// Limits defines finite caps for CGGMP21 secp256k1 protocol parameters.
type Limits struct {
	Threshold tss.ThresholdLimits
	State     StateLimits
	Payload   PayloadLimits
	Curve     CurveLimits
	Paillier  PaillierLimits
	ZK        ZKLimits
	SignPrep  SignPrepLimits
	TLV       tss.TLVLimits
}

// testDefaultLimits allows TestMain to apply relaxed limits to all tests
// without global mutable state. Set by TestMain; nil means use production defaults.
var testDefaultLimits *Limits

// DefaultLimits returns fail-closed production limits for CGGMP21 secp256k1.
// It rejects 1-of-1, oversized signer sets, and thresholds below 2.
func DefaultLimits() Limits {
	if testDefaultLimits != nil {
		return *testDefaultLimits
	}
	return Limits{
		Threshold: tss.ThresholdLimits{
			MaxParties:              maxCGGMPParties,
			MaxThreshold:            maxCGGMPThreshold,
			MaxSigners:              maxCGGMPSigners,
			MinProductionThreshold:  2,
			AllowOneOfOne:           false,
			AllowOversizedSignerSet: false,
		},
		State: StateLimits{
			MaxSerializedKeyShareBytes:    tss.DefaultMaxSerializedKeyShareBytes,
			MaxSerializedPresignBytes:     tss.DefaultMaxSerializedPresignBytes,
			MaxSerializedResharePlanBytes: tss.DefaultMaxSerializedResharePlanBytes,
			MaxSerializedSignAttemptBytes: tss.DefaultMaxEnvelopeBytes + 4096,
		},
		Payload: PayloadLimits{
			MaxMessageBytes: 65536,
		},
		Curve: CurveLimits{
			MaxPointBytes:  65,
			MaxScalarBytes: 32,
		},
		Paillier: PaillierLimits{
			MaxModulusBits:       tss.DefaultMaxPaillierModulusBits,
			MaxPublicKeyBytes:    tss.DefaultMaxPaillierPublicKeyBytes,
			MaxPrivateKeyBytes:   tss.DefaultMaxPaillierPrivateKeyBytes,
			MaxCiphertextBytes:   tss.DefaultMaxPaillierCiphertextBytes,
			MaxRingPedersenBytes: tss.DefaultMaxRingPedersenParamsBytes,
			MaxProofBytes:        tss.DefaultMaxPaillierProofBytes,
			MaxMTAResponseBytes:  tss.DefaultMaxMTAResponseBytes,
		},
		ZK: ZKLimits{
			MaxProofBytes: tss.DefaultMaxZKProofBytes,
		},
		SignPrep: SignPrepLimits{
			MaxProofBytes:              maxSignPrepProofBytes,
			MaxVerifyShareBytes:        maxSignVerifyShareBytes,
			MaxVerifySharesBytes:       maxSignVerifySharesBytes,
			MaxSignPartialPayloadBytes: maxSignPartialPayloadBytes,
		},
		TLV: tss.TLVLimits{
			MaxFields:     tss.DefaultMaxWireFields,
			MaxFieldBytes: tss.DefaultMaxWireFieldBytes,
		},
	}
}

// TestLimits returns relaxed limits for CGGMP21 test code only.
func TestLimits() Limits {
	return Limits{
		Threshold: tss.ThresholdLimits{
			MaxParties:              8,
			MaxThreshold:            8,
			MaxSigners:              8,
			MinProductionThreshold:  1,
			AllowOneOfOne:           true,
			AllowOversizedSignerSet: true,
		},
		State: StateLimits{
			MaxSerializedKeyShareBytes:    tss.DefaultMaxSerializedKeyShareBytes,
			MaxSerializedPresignBytes:     tss.DefaultMaxSerializedPresignBytes,
			MaxSerializedResharePlanBytes: tss.DefaultMaxSerializedResharePlanBytes,
			MaxSerializedSignAttemptBytes: tss.DefaultMaxEnvelopeBytes + 4096,
		},
		Payload: PayloadLimits{
			MaxMessageBytes: 65536,
		},
		Curve: CurveLimits{
			MaxPointBytes:  65,
			MaxScalarBytes: 32,
		},
		Paillier: PaillierLimits{
			MaxModulusBits:       8192,
			MaxPublicKeyBytes:    4096,
			MaxPrivateKeyBytes:   8192,
			MaxCiphertextBytes:   4096,
			MaxRingPedersenBytes: 16384,
			MaxProofBytes:        512 << 10,
			MaxMTAResponseBytes:  512 << 10,
		},
		ZK: ZKLimits{
			MaxProofBytes: 512 << 10,
		},
		SignPrep: SignPrepLimits{
			MaxProofBytes:              512 << 10,
			MaxVerifyShareBytes:        maxSignVerifyShareBytes,
			MaxVerifySharesBytes:       maxSignVerifySharesBytes,
			MaxSignPartialPayloadBytes: maxSignPartialPayloadBytes,
		},
		TLV: tss.TLVLimits{
			MaxFields:     tss.DefaultMaxWireFields,
			MaxFieldBytes: tss.DefaultMaxWireFieldBytes,
		},
	}
}

// ThresholdLimits returns the threshold portion of the limits for use with
// tss.ThresholdConfig.ValidateWithLimits and tss.ValidateSignerSet.
func (l Limits) ThresholdLimits() tss.ThresholdLimits {
	return l.Threshold
}

// frameLimits converts TLV limits to wire.FrameLimits for the given total byte cap.
func (l Limits) frameLimits(maxTotal int) wire.FrameLimits {
	return wire.FrameLimits{
		MaxTotalBytes: maxTotal,
		MaxFields:     l.TLV.MaxFields,
		MaxFieldBytes: l.TLV.MaxFieldBytes,
	}
}

// fieldLimits returns semantic field limits for CGGMP21 wire encoding tags.
func (l Limits) fieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"curve_id":                   32,
		"scalar":                     l.Curve.MaxScalarBytes,
		"point":                      l.Curve.MaxPointBytes,
		"parties":                    l.Threshold.MaxParties,
		"threshold":                  l.Threshold.MaxThreshold,
		"signers":                    l.Threshold.MaxSigners,
		"paillier_modulus_bits":      l.Paillier.MaxModulusBits,
		"paillier_public_key":        l.Paillier.MaxPublicKeyBytes,
		"paillier_private_key":       l.Paillier.MaxPrivateKeyBytes,
		"paillier_ciphertext":        l.Paillier.MaxCiphertextBytes,
		"paillier_proof":             l.Paillier.MaxProofBytes,
		"ring_pedersen_params":       l.Paillier.MaxRingPedersenBytes,
		"mta_response":               l.Paillier.MaxMTAResponseBytes,
		"zk_proof":                   l.ZK.MaxProofBytes,
		"signprep_proof":             l.SignPrep.MaxProofBytes,
		"signprep_verify_share":      l.SignPrep.MaxVerifyShareBytes,
		"signprep_verify_shares":     l.SignPrep.MaxVerifySharesBytes,
		"signprep_partial_signature": l.SignPrep.MaxSignPartialPayloadBytes,
		"envelope":                   tss.DefaultMaxEnvelopeBytes,
	}
}
