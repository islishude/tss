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
	// Πfac responses are products of at most the prover and verifier moduli
	// plus the public mask/challenge widths. Four KiB covers the largest
	// supported profile without permitting attacker-selected multi-megabit
	// exponents to reach big.Int modular exponentiation.
	maxFactorResponseBytes = 4096

	maxSignPrepProofBytes         = 512 << 10
	maxSignVerifyShareRecordBytes = signVerifyShareRecordFixedBytes + 65*6 + 32*2 + maxSignPrepProofBytes
	maxSignVerifyShareBytes       = maxSignVerifyShareRecordBytes
	maxSignVerifySharesBytes      = 4 + maxCGGMPSigners*(4+maxSignVerifyShareRecordBytes)
	maxSignPartialPayloadBytes    = 32*6 + maxSignPrepProofBytes + 256
	// Identification evidence uses the certified envelope as its canonical proof
	// carrier inside the 1 MiB public-evidence hard cap. Keep the phase payload
	// below half that budget, leaving room for the compact public statement,
	// sixteen maximum-size ACKs, and TLV framing.
	maxIdentificationPayloadBytes    = 384 << 10
	maxPresignVerificationEntryBytes = tss.DefaultMaxPaillierCiphertextBytes*2 +
		tss.DefaultMaxPaillierPublicKeyBytes + 256
	maxPresignVerificationContextBytes          = 4 + maxCGGMPSigners*(4+maxPresignVerificationEntryBytes)
	maxSerializedPresignWithIdentificationBytes = 16 << 20
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
	MaxProofBytes               int
	MaxVerifyShareBytes         int
	MaxVerifySharesBytes        int
	MaxSignPartialPayloadBytes  int
	MaxVerificationEntryBytes   int
	MaxVerificationContextBytes int
}

// Limits defines local fail-closed resource and policy bounds for CGGMP21.
// Limits are not shared protocol intent and are not included in plan digests.
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

// DefaultLimits returns fail-closed production limits for CGGMP21 secp256k1.
// It rejects 1-of-1, oversized signer sets, and thresholds below 2.
func DefaultLimits() Limits {
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
			MaxSerializedPresignBytes:     maxSerializedPresignWithIdentificationBytes,
			MaxSerializedResharePlanBytes: tss.DefaultMaxSerializedResharePlanBytes,
			MaxSerializedSignAttemptBytes: tss.DefaultMaxEnvelopeBytes + 4096,
		},
		Payload: PayloadLimits{
			MaxMessageBytes: tss.DefaultMaxEnvelopePayloadBytes,
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
			MaxProofBytes:               maxSignPrepProofBytes,
			MaxVerifyShareBytes:         maxSignVerifyShareBytes,
			MaxVerifySharesBytes:        maxSignVerifySharesBytes,
			MaxSignPartialPayloadBytes:  maxSignPartialPayloadBytes,
			MaxVerificationEntryBytes:   maxPresignVerificationEntryBytes,
			MaxVerificationContextBytes: maxPresignVerificationContextBytes,
		},
		TLV: tss.TLVLimits{
			MaxFields:     tss.DefaultMaxWireFields,
			MaxFieldBytes: tss.DefaultMaxWireFieldBytes,
		},
	}
}

func limitsOrDefault(limits *Limits) Limits {
	if limits == nil {
		return DefaultLimits()
	}
	return *limits
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
		"protocol_name":              tss.DefaultMaxProtocolNameBytes,
		"payload_type":               tss.DefaultMaxPayloadTypeBytes,
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
		"paillier_modulus":           l.Paillier.MaxCiphertextBytes,
		"signed_response":            l.Paillier.MaxCiphertextBytes,
		"paillier_signed":            l.Paillier.MaxCiphertextBytes,
		"factor_response":            maxFactorResponseBytes,
		"proof_rounds":               128,
		"signprep_proof":             l.SignPrep.MaxProofBytes,
		"signprep_partial_signature": l.SignPrep.MaxSignPartialPayloadBytes,
		"envelope":                   tss.DefaultMaxEnvelopeBytes,
		"broadcast_signature":        tss.DefaultMaxWireFieldBytes,
		"broadcast_recipients":       l.Threshold.MaxParties,
	}
}
