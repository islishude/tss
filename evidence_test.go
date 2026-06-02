package tss

import (
	"bytes"
	"strings"
	"testing"
)

func TestBlameEvidenceField(t *testing.T) {
	makeEvidence := func(t *testing.T) *BlameEvidence {
		t.Helper()
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
		evidence, err := NewBlameEvidence(env, EvidenceKindSignPartial, "invalid partial", []EvidenceField{
			{Key: "sender_commitment", Value: []byte{0x01, 0x02, 0x03}},
			{Key: "proof_response", Value: []byte{0xaa, 0xbb}},
			{Key: "another_field", Value: []byte{}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return evidence
	}

	t.Run("nil receiver", func(t *testing.T) {
		var e *BlameEvidence
		val, ok := e.Field("any")
		if ok {
			t.Error("expected false for nil receiver")
		}
		if val != nil {
			t.Errorf("expected nil value, got %v", val)
		}
	})

	t.Run("existing field returns clone", func(t *testing.T) {
		e := makeEvidence(t)
		val, ok := e.Field("sender_commitment")
		if !ok {
			t.Fatal("expected to find sender_commitment")
		}
		if !bytes.Equal(val, []byte{0x01, 0x02, 0x03}) {
			t.Errorf("got %v, want [1 2 3]", val)
		}
		// Mutating the returned value must not affect the evidence.
		val[0] = 0xff
		original, _ := e.Field("sender_commitment")
		if bytes.Equal(original, val) {
			t.Error("Field must return a clone, mutation leaked back")
		}
	})

	t.Run("non-existent field", func(t *testing.T) {
		e := makeEvidence(t)
		val, ok := e.Field("no_such_key")
		if ok {
			t.Error("expected false for missing key")
		}
		if val != nil {
			t.Errorf("expected nil value, got %v", val)
		}
	})

	t.Run("empty key", func(t *testing.T) {
		e := makeEvidence(t)
		val, ok := e.Field("")
		if ok {
			t.Error("expected false for empty key (normalizeEvidenceFields rejects empty keys)")
		}
		if val != nil {
			t.Errorf("expected nil, got %v", val)
		}
	})

	t.Run("finds correct field among multiple", func(t *testing.T) {
		e := makeEvidence(t)
		val, ok := e.Field("another_field")
		if !ok {
			t.Fatal("expected to find another_field")
		}
		if val == nil {
			t.Fatal("expected non-nil value for empty-byte field")
		}
		if len(val) != 0 {
			t.Errorf("expected empty slice, got %v", val)
		}
	})

	t.Run("case sensitive", func(t *testing.T) {
		e := makeEvidence(t)
		_, ok := e.Field("Sender_Commitment")
		if ok {
			t.Error("Field lookup must be case-sensitive")
		}
	})

	t.Run("no public inputs", func(t *testing.T) {
		e := &BlameEvidence{PublicInputs: nil}
		_, ok := e.Field("anything")
		if ok {
			t.Error("expected false when PublicInputs is nil")
		}
		e2 := &BlameEvidence{PublicInputs: []EvidenceField{}}
		_, ok = e2.Field("anything")
		if ok {
			t.Error("expected false when PublicInputs is empty")
		}
	})

	t.Run("returns clone with independent backing array", func(t *testing.T) {
		e := makeEvidence(t)
		val, ok := e.Field("proof_response")
		if !ok {
			t.Fatal("expected to find proof_response")
		}
		// Overwrite entire buffer to verify no aliasing.
		for i := range val {
			val[i] = 0
		}
		original, _ := e.Field("proof_response")
		if !bytes.Equal(original, []byte{0xaa, 0xbb}) {
			t.Error("Field must return a deep copy, not a shared slice")
		}
	})
}

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
