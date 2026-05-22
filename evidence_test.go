package tss

import (
	"bytes"
	"strings"
	"testing"
)

func TestBlameEvidenceMarshalDeterministic(t *testing.T) {
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{
		Protocol:    "test-protocol",
		Version:     Version,
		SessionID:   session,
		Round:       2,
		From:        1,
		To:          2,
		PayloadType: "test.payload",
		Payload:     []byte("public payload"),
	}.WithTranscriptHash()
	evidence, err := NewBlameEvidence(env, EvidenceKindPresignRound2, "invalid proof", []EvidenceField{
		{Key: "z_field", Value: []byte{3}},
		{Key: "a_field", Value: []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	second, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("evidence encoding is not deterministic")
	}
	decoded, err := UnmarshalBlameEvidence(first)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicInputs[0].Key != "a_field" {
		t.Fatal("evidence fields were not canonicalized")
	}
	hash1, err := evidence.Hash()
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := decoded.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash1, hash2) {
		t.Fatal("evidence hash changed after round trip")
	}
}

func TestBlameEvidenceRejectsMalformed(t *testing.T) {
	if _, err := UnmarshalBlameEvidence([]byte(`{"version":1}`)); err == nil {
		t.Fatal("malformed evidence decoded")
	}
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{
		Protocol:    "test-protocol",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "test.payload",
	}.WithTranscriptHash()
	if _, err := NewBlameEvidence(env, EvidenceKindSignPartial, "invalid partial", []EvidenceField{
		{Key: "dup", Value: []byte{1}},
		{Key: "dup", Value: []byte{2}},
	}); err == nil {
		t.Fatal("duplicate evidence field accepted")
	}
}

func TestBlameEvidenceDoesNotNameSecretFields(t *testing.T) {
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{
		Protocol:    "test-protocol",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "test.payload",
		Payload:     []byte("public payload"),
	}.WithTranscriptHash()
	evidence, err := NewBlameEvidence(env, EvidenceKindAggregateSign, "aggregate check failed", []EvidenceField{
		{Key: "public_key_hash", Value: []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"secret", "nonce", "k_share", "sigma_share", "paillier_private"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("evidence contains sensitive field marker %q: %s", forbidden, encoded)
		}
	}
}
