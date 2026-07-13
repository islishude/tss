package ed25519

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// FROST Ed25519 algorithm-specific limits.
const (
	maxFROSTParties   = 64
	maxFROSTThreshold = 64
	maxFROSTSigners   = 64
)

// StateLimits caps serialized FROST key material.
type StateLimits struct {
	MaxSerializedKeyShareBytes                  int
	MaxSerializedTrustedDealerPlanBytes         int
	MaxSerializedTrustedDealerContributionBytes int
}

// PayloadLimits caps FROST payload sizes.
type PayloadLimits struct {
	MaxMessageBytes           int
	MaxSerializedPayloadBytes int
}

// CurveLimits caps Ed25519 curve point and scalar encoding sizes.
type CurveLimits struct {
	MaxPointBytes  int
	MaxScalarBytes int
}

// Limits defines local fail-closed resource and policy bounds for FROST.
// Limits are not shared protocol intent and are not included in plan digests.
type Limits struct {
	Threshold tss.ThresholdLimits
	State     StateLimits
	Payload   PayloadLimits
	Curve     CurveLimits
	TLV       tss.TLVLimits
}

// DefaultLimits returns fail-closed production limits for FROST Ed25519.
// It rejects 1-of-1, oversized signer sets, and thresholds below 2.
func DefaultLimits() Limits {
	return Limits{
		Threshold: tss.ThresholdLimits{
			MaxParties:              maxFROSTParties,
			MaxThreshold:            maxFROSTThreshold,
			MaxSigners:              maxFROSTSigners,
			MinProductionThreshold:  2,
			AllowOneOfOne:           false,
			AllowOversizedSignerSet: false,
		},
		State: StateLimits{
			MaxSerializedKeyShareBytes:                  tss.DefaultMaxSerializedKeyShareBytes,
			MaxSerializedTrustedDealerPlanBytes:         tss.DefaultMaxSerializedTrustedDealerPlanBytes,
			MaxSerializedTrustedDealerContributionBytes: tss.DefaultMaxSerializedTrustedDealerContributionBytes,
		},
		Payload: PayloadLimits{
			MaxMessageBytes:           65536,
			MaxSerializedPayloadBytes: tss.DefaultMaxWireFieldBytes,
		},
		Curve: CurveLimits{
			MaxPointBytes:  32,
			MaxScalarBytes: 32,
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

func (l Limits) payloadFrameLimits() wire.FrameLimits {
	return l.frameLimits(l.Payload.MaxSerializedPayloadBytes)
}

// fieldLimits returns semantic field limits for FROST wire encoding tags.
func (l Limits) fieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"scalar":    l.Curve.MaxScalarBytes,
		"point":     l.Curve.MaxPointBytes,
		"parties":   l.Threshold.MaxParties,
		"threshold": l.Threshold.MaxThreshold,
		"signers":   l.Threshold.MaxSigners,
	}
}
