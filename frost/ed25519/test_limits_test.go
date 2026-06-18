package ed25519

import "github.com/islishude/tss"

func testLimits() Limits {
	limits := DefaultLimits()
	limits.Threshold.MaxParties = 8
	limits.Threshold.MaxThreshold = 8
	limits.Threshold.MaxSigners = 8
	limits.Threshold.MinProductionThreshold = 1
	limits.Threshold.AllowOneOfOne = true
	limits.Threshold.AllowOversizedSignerSet = true
	return limits
}

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	return marshalKeygenCommitmentsPayloadWithLimits(p, testLimits())
}

func unmarshalKeygenCommitmentsPayload(in []byte) (keygenCommitmentsPayload, error) {
	return tss.DecodeBinaryValueWithLimits[keygenCommitmentsPayload](in, testLimits())
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	return marshalKeygenSharePayloadWithLimits(p, testLimits())
}

func unmarshalKeygenSharePayload(in []byte) (keygenSharePayload, error) {
	return tss.DecodeBinaryValueWithLimits[keygenSharePayload](in, testLimits())
}

func marshalNonceCommitmentPayload(p nonceCommitment) ([]byte, error) {
	return marshalNonceCommitmentPayloadWithLimits(p, testLimits())
}

func unmarshalNonceCommitmentPayload(in []byte) (nonceCommitment, error) {
	return tss.DecodeBinaryValueWithLimits[nonceCommitment](in, testLimits())
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	return marshalSignPartialPayloadWithLimits(p, testLimits())
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	return tss.DecodeBinaryValueWithLimits[signPartialPayload](in, testLimits())
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	return marshalReshareSharePayloadWithLimits(p, testLimits())
}

func unmarshalReshareSharePayload(in []byte) (reshareSharePayload, error) {
	return tss.DecodeBinaryValueWithLimits[reshareSharePayload](in, testLimits())
}
