package secp256k1

import (
	"github.com/islishude/tss"
)

func testLimits() Limits {
	limits := DefaultLimits()
	limits.Threshold = tss.ThresholdLimits{
		MaxParties:              8,
		MaxThreshold:            8,
		MaxSigners:              8,
		MinProductionThreshold:  1,
		AllowOneOfOne:           true,
		AllowOversizedSignerSet: true,
	}
	limits.Paillier = PaillierLimits{
		MaxModulusBits:       8192,
		MaxPublicKeyBytes:    4096,
		MaxPrivateKeyBytes:   8192,
		MaxCiphertextBytes:   4096,
		MaxProofBytes:        512 << 10,
		MaxRingPedersenBytes: 16384,
		MaxMTAResponseBytes:  512 << 10,
	}
	limits.ZK.MaxProofBytes = 512 << 10
	limits.SignPrep.MaxProofBytes = 512 << 10
	return limits
}

func testSecurityParams() SecurityParams {
	return SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
}

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	return marshalKeygenCommitmentsPayloadWithLimits(p, testLimits())
}

func unmarshalKeygenCommitmentsPayload(in []byte) (keygenCommitmentsPayload, error) {
	return unmarshalKeygenCommitmentsPayloadWithLimits(in, testLimits())
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	return marshalKeygenSharePayloadWithLimits(p, testLimits())
}

func unmarshalKeygenSharePayload(in []byte) (keygenSharePayload, error) {
	return unmarshalKeygenSharePayloadWithLimits(in, testLimits())
}

func marshalPresignRound1Payload(p presignRound1Payload) ([]byte, error) {
	return marshalPresignRound1PayloadWithLimits(p, testLimits())
}

func unmarshalPresignRound1Payload(in []byte) (presignRound1Payload, error) {
	return unmarshalPresignRound1PayloadWithLimits(in, testLimits())
}

func marshalPresignRound1ProofPayload(p presignRound1ProofPayload) ([]byte, error) {
	return marshalPresignRound1ProofPayloadWithLimits(p, testLimits())
}

func unmarshalPresignRound1ProofPayload(in []byte) (presignRound1ProofPayload, error) {
	return unmarshalPresignRound1ProofPayloadWithLimits(in, testLimits())
}

func marshalPresignRound2Payload(p presignRound2Payload) ([]byte, error) {
	return marshalPresignRound2PayloadWithLimits(p, testLimits())
}

func unmarshalPresignRound2Payload(in []byte) (presignRound2Payload, error) {
	return unmarshalPresignRound2PayloadWithLimits(in, testLimits())
}

func marshalPresignRound3Payload(p presignRound3Payload) ([]byte, error) {
	return marshalPresignRound3PayloadWithLimits(p, testLimits())
}

func unmarshalPresignRound3Payload(in []byte) (presignRound3Payload, error) {
	return unmarshalPresignRound3PayloadWithLimits(in, testLimits())
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	return marshalSignPartialPayloadWithLimits(p, testLimits())
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	return unmarshalSignPartialPayloadWithLimits(in, testLimits())
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	return marshalReshareSharePayloadWithLimits(p, testLimits())
}

func unmarshalReshareSharePayload(in []byte) (reshareSharePayload, error) {
	return unmarshalReshareSharePayloadWithLimits(in, testLimits())
}

func unmarshalRefreshCommitmentsPayload(in []byte) (refreshCommitmentsPayload, error) {
	return unmarshalRefreshCommitmentsPayloadWithLimits(in, testLimits())
}

func marshalRefreshSharePayload(p refreshSharePayload) ([]byte, error) {
	return marshalRefreshSharePayloadWithLimits(p, testLimits())
}

func unmarshalRefreshSharePayload(in []byte) (refreshSharePayload, error) {
	return unmarshalRefreshSharePayloadWithLimits(in, testLimits())
}
