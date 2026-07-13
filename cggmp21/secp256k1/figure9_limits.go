package secp256k1

import "github.com/islishude/tss"

const (
	maxFigure9PayloadBytes  = 24 << 20
	maxFigure9EnvelopeBytes = 32 << 20
	maxFigure9EvidenceBytes = 32 << 20
)

// Figure9EnvelopeLimits returns the explicit envelope limits required by the
// single-message Figure 9 attributable-abort proof. Ordinary envelopes keep
// the conservative 1 MiB defaults.
func Figure9EnvelopeLimits() tss.EnvelopeLimits {
	limits := tss.DefaultEnvelopeLimits()
	limits.MaxBytes = maxFigure9EnvelopeBytes
	limits.MaxPayloadBytes = maxFigure9PayloadBytes
	limits.TLV.MaxFieldBytes = maxFigure9PayloadBytes
	return limits
}

func figure9EvidenceLimits() tss.EvidenceLimits {
	limits := tss.DefaultEvidenceLimits()
	limits.MaxBytes = maxFigure9EvidenceBytes
	limits.MaxFieldValueBytes = maxFigure9EvidenceBytes
	limits.TLV.MaxFieldBytes = maxFigure9EvidenceBytes
	return limits
}

func figure9IdentificationRecordLimits() tss.IdentificationRecordLimits {
	limits := tss.DefaultIdentificationRecordLimits()
	limits.MaxBytes = maxFigure9EvidenceBytes
	limits.MaxEnvelopeBytes = maxFigure9EnvelopeBytes
	limits.MaxStatementBytes = maxFigure9PayloadBytes
	limits.MaxProofBytes = maxFigure9PayloadBytes
	limits.TLV.MaxFieldBytes = maxFigure9EnvelopeBytes
	return limits
}

func isFigure9Envelope(env tss.Envelope) bool {
	return env.Protocol == tss.ProtocolCGGMP21Secp256k1 &&
		env.Round == presignRedAlertRound &&
		env.PayloadType == payloadPresignRedAlert
}

func envelopeLimitsForEvidence(env tss.Envelope) tss.EnvelopeLimits {
	if isFigure9Envelope(env) {
		return Figure9EnvelopeLimits()
	}
	return defaultEnvelopeLimitsForEvidence()
}

func evidenceLimitsForKind(kind tss.EvidenceKind) tss.EvidenceLimits {
	if kind == tss.EvidenceKindPresignRedAlert {
		return figure9EvidenceLimits()
	}
	return tss.DefaultEvidenceLimits()
}

func identificationLimitsForKind(kind tss.EvidenceKind) tss.IdentificationRecordLimits {
	if kind == tss.EvidenceKindPresignRedAlert {
		return figure9IdentificationRecordLimits()
	}
	return tss.DefaultIdentificationRecordLimits()
}
