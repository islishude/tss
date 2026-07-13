package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestFigure9EnvelopeLimitsAreExplicit(t *testing.T) {
	var sessionID tss.SessionID
	sessionID[0] = 1
	payload := make([]byte, tss.DefaultMaxEnvelopePayloadBytes+1)
	input := tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: presignRedAlertRound, From: 1, To: tss.BroadcastPartyId,
		PayloadType: payloadPresignRedAlert, Payload: payload,
	}
	if _, err := tss.NewEnvelope(input); err == nil {
		t.Fatal("default 1 MiB envelope limit accepted a Figure 9 payload")
	}
	env, err := tss.NewEnvelopeWithLimits(input, Figure9EnvelopeLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.MarshalBinary(); err == nil {
		t.Fatal("default envelope marshal accepted a Figure 9 payload")
	}
	raw, err := env.MarshalBinaryWithLimits(Figure9EnvelopeLimits())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tss.UnmarshalEnvelopeWithLimits(raw, Figure9EnvelopeLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatal("Figure 9 envelope payload changed during round trip")
	}

	tooLargePayload := make([]byte, maxFigure9PayloadBytes+1)
	input.Payload = tooLargePayload
	if _, err := tss.NewEnvelopeWithLimits(input, Figure9EnvelopeLimits()); err == nil {
		t.Fatal("explicit Figure 9 limits accepted a payload above 24 MiB")
	}

	oversizedRaw := make([]byte, maxFigure9EnvelopeBytes+1)
	copy(oversizedRaw, raw)
	if _, err := tss.UnmarshalEnvelopeWithLimits(oversizedRaw, Figure9EnvelopeLimits()); err == nil {
		t.Fatal("explicit Figure 9 limits accepted an envelope above 32 MiB")
	}
}

func TestFigure9EvidenceLimitsDoNotWidenDefaults(t *testing.T) {
	proof := make([]byte, tss.DefaultMaxZKProofBytes+1)
	record := &tss.IdentificationRecord{
		FailureClass: "presign_figure9_nonce", Accused: 1, Statement: []byte{1}, Proof: proof,
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	if _, err := tss.IdentificationEvidenceField(record); err == nil {
		t.Fatal("default identification limits accepted an oversized proof")
	}
	if _, err := tss.IdentificationEvidenceFieldWithLimits(record, figure9IdentificationRecordLimits()); err != nil {
		t.Fatal(err)
	}

	var sessionID tss.SessionID
	sessionID[0] = 1
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: presignRedAlertRound, From: 1, PayloadType: payloadPresignRedAlert,
		Payload: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	largeField := tss.EvidenceField{Key: "figure9_record", Value: make([]byte, tss.DefaultMaxEvidenceFieldValueBytes+1)}
	if _, err := tss.NewBlameEvidence(env, tss.EvidenceKindPresignRedAlert, "invalid Figure 9 proof", []tss.EvidenceField{largeField}); err == nil {
		t.Fatal("default evidence limits accepted an oversized public field")
	}
	evidence, err := tss.NewBlameEvidenceWithLimits(env, tss.EvidenceKindPresignRedAlert,
		"invalid Figure 9 proof", []tss.EvidenceField{largeField}, figure9EvidenceLimits())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := evidence.MarshalBinaryWithLimits(figure9EvidenceLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[tss.BlameEvidence](encoded); err == nil {
		t.Fatal("default evidence decoder accepted Figure 9-sized evidence")
	}
	if _, err := tss.UnmarshalBlameEvidenceWithLimits(encoded, figure9EvidenceLimits()); err != nil {
		t.Fatal(err)
	}
}
