package tss

import (
	"bytes"
	"testing"
)

func TestIdentificationRecordBindsAccusedProofAndTranscript(t *testing.T) {
	t.Parallel()
	record := IdentificationRecord{
		FailureClass: "test-invalid-proof",
		Accused:      2,
		Statement:    bytes.Repeat([]byte{0x11}, 32),
		Proof:        []byte("public-proof"),
		TranscriptHashes: []EvidenceField{
			{Key: "protocol_alert_digest", Value: bytes.Repeat([]byte{0x22}, 32)},
		},
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	raw, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded IdentificationRecord
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}

	mutations := []func(*IdentificationRecord){
		func(r *IdentificationRecord) { r.Accused++ },
		func(r *IdentificationRecord) { r.Proof[0] ^= 1 },
		func(r *IdentificationRecord) { r.Statement[0] ^= 1 },
		func(r *IdentificationRecord) { r.TranscriptHashes[0].Value[0] ^= 1 },
	}
	for i, mutate := range mutations {
		candidate := decoded.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("mutation %d retained the original alert binding", i)
		}
	}
}

func TestIdentificationRecordRejectsNonCanonicalTranscriptHashes(t *testing.T) {
	t.Parallel()
	record := IdentificationRecord{
		FailureClass: "test-invalid-proof",
		Accused:      2,
		Statement:    bytes.Repeat([]byte{0x11}, 32),
		Proof:        []byte("public-proof"),
		TranscriptHashes: []EvidenceField{
			{Key: "z", Value: bytes.Repeat([]byte{0x22}, 32)},
			{Key: "a", Value: bytes.Repeat([]byte{0x33}, 32)},
		},
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	if err := record.Validate(); err == nil {
		t.Fatal("accepted non-canonical transcript hash order")
	}
}
