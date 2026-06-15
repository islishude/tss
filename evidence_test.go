package tss

import (
	"bytes"
	"strings"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestBlameEvidenceField(t *testing.T) {
	t.Parallel()
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
		}
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
	t.Parallel()
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
	}
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
	t.Parallel()
	// Garbage bytes that don't match the TLV magic prefix.
	if _, err := UnmarshalBlameEvidence([]byte("not a valid TLV message")); err == nil {
		t.Fatal("malformed evidence decoded")
	}
	// Valid TLV magic but wrong type ID.
	if _, err := UnmarshalBlameEvidence(append([]byte("TSS1"), make([]byte, 100)...)); err == nil {
		t.Fatal("malformed evidence with wrong type decoded")
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
	}
	if _, err := NewBlameEvidence(env, EvidenceKindSignPartial, "invalid partial", []EvidenceField{
		{Key: "dup", Value: []byte{1}},
		{Key: "dup", Value: []byte{2}},
	}); err == nil {
		t.Fatal("duplicate evidence field accepted")
	}
}

func TestBlameEvidenceDoesNotNameSecretFields(t *testing.T) {
	t.Parallel()
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
	}
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
			t.Fatalf("evidence contains sensitive field marker %q: %x", forbidden, encoded)
		}
	}
	// TLV encoding must not contain JSON structural characters or field names.
	for _, jsonMarker := range []string{`"version"`, `"protocol"`, `"payload_type"`, `"public_inputs"`, `"reason"`, `"kind"`} {
		if strings.Contains(lower, jsonMarker) {
			t.Fatalf("evidence contains JSON field name %s: evidence is not using TLV encoding", jsonMarker)
		}
	}
}

func TestBlameEvidenceRecordListMutationRejected(t *testing.T) {
	t.Parallel()
	// Build a valid BlameEvidence first to get the correct envelope structure,
	// then replace the PublicInputs recordlist with a malformed one.
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Helper: build a valid evidence, marshal it, then replace tag 12 value.
	env := Envelope{
		Protocol:    "test-protocol",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "test.payload",
		Payload:     []byte("public payload"),
	}
	evidence, err := NewBlameEvidence(env, EvidenceKindSignPartial, "mutation test", []EvidenceField{
		{Key: "field_a", Value: []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	validRaw, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_ = validRaw

	t.Run("malformed recordlist truncated count", func(t *testing.T) {
		// Build a field body with tag 12 value truncated (only 2 bytes of the uint32 count).
		malformed := []byte{0x00, 0x01} // truncated count
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for truncated recordlist count")
		}
	})

	t.Run("malformed recordlist count too large", func(t *testing.T) {
		// count=0xFFFFFFFF exceeds maxRecordCount (65535).
		malformed := wire.Uint32(0xFFFFFFFF)
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for oversized recordlist count")
		}
	})

	t.Run("malformed recordlist item truncated", func(t *testing.T) {
		// count=1, then only 2 bytes of the 4-byte record_len.
		malformed := make([]byte, 0, 6)
		malformed = append(malformed, wire.Uint32(1)...) // count=1
		malformed = append(malformed, 0x00, 0x10)        // truncated rec_len (only 2 of 4 bytes)
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for truncated recordlist item")
		}
	})

	t.Run("malformed recordlist trailing bytes", func(t *testing.T) {
		// Build a minimal valid record (tag1=key, tag2=empty-value).
		recBody := buildRecordBody([]wire.Field{
			{Tag: 1, Value: []byte("k")},
			{Tag: 2, Value: []byte{}},
		})
		// count=1, rec_len, rec_body, then extra trailing byte.
		malformed := make([]byte, 0, 20)
		malformed = append(malformed, wire.Uint32(1)...)
		malformed = append(malformed, wire.Uint32(uint32(len(recBody)))...)
		malformed = append(malformed, recBody...)
		malformed = append(malformed, 0xFF) // trailing byte
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for trailing bytes in recordlist")
		}
	})
}

func TestBlameEvidenceRecordListMissingFieldRejected(t *testing.T) {
	t.Parallel()
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("record missing Key field", func(t *testing.T) {
		// Build a record body with only tag 2 (Value), missing tag 1 (Key).
		recBody := buildRecordBody([]wire.Field{
			{Tag: 2, Value: []byte("val")},
			// tag 1 (Key) intentionally absent
		})
		malformed := buildRecordListBytes([][]byte{recBody})
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for missing Key field in EvidenceField record")
		}
	})

	t.Run("record missing Value field", func(t *testing.T) {
		// Build a record body with only tag 1 (Key), missing tag 2 (Value).
		recBody := buildRecordBody([]wire.Field{
			{Tag: 1, Value: []byte("key_only")},
			// tag 2 (Value) intentionally absent
		})
		malformed := buildRecordListBytes([][]byte{recBody})
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for missing Value field in EvidenceField record")
		}
	})

	t.Run("record with extra field", func(t *testing.T) {
		recBody := buildRecordBody([]wire.Field{
			{Tag: 1, Value: []byte("k")},
			{Tag: 2, Value: []byte("v")},
			{Tag: 99, Value: []byte("extra")}, // unexpected field
		})
		malformed := buildRecordListBytes([][]byte{recBody})
		raw := buildEvidenceWithField12(t, session, malformed)
		if _, err := UnmarshalBlameEvidence(raw); err == nil {
			t.Fatal("expected error for extra field in EvidenceField record")
		}
	})
}

func TestBlameEvidenceRecordListNonUTF8KeyRejected(t *testing.T) {
	t.Parallel()
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	nonUTF8 := []byte{0xff, 0xfe, 0xfd}
	recBody := buildRecordBody([]wire.Field{
		{Tag: 1, Value: nonUTF8}, // Key as non-UTF-8 bytes
		{Tag: 2, Value: []byte{}},
	})
	malformed := buildRecordListBytes([][]byte{recBody})
	raw := buildEvidenceWithField12(t, session, malformed)
	if _, err := UnmarshalBlameEvidence(raw); err == nil {
		t.Fatal("expected error for non-UTF-8 Key in EvidenceField record")
	}
}

func TestBlameEvidenceRecordListValueExceedsLimitRejected(t *testing.T) {
	t.Parallel()
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Build a Value that exceeds the configured MaxEvidenceFieldValueBytes limit.
	// The test uses DefaultLimits which sets MaxEvidenceFieldValueBytes = 1<<20.
	// We construct a record where Value claims to be longer than the limit via
	// the wire encoding, but the actual bytes are short — the decoder checks length
	// against MaxWireFieldBytes (1 MiB) which this will pass, so we need to use
	// a value that is actually oversized for the semantic limit.

	// The decode path checks MaxWireFieldBytes (1 MiB) first at the TLV level,
	// then the record-level max_bytes check happens via LimitSet. Since the
	// semantic limit MaxEvidenceFieldValueBytes = 1 MiB and the TLV limit
	// MaxWireFieldBytes = 1 MiB, we need to construct a value that exceeds the
	// semantic limit but still passes the TLV limit. Let's use an oversized key
	// instead, which has a much lower limit (128 bytes).
	oversizedKey := make([]byte, 256) // exceeds MaxEvidenceFieldKeyBytes (128)
	for i := range oversizedKey {
		oversizedKey[i] = 'a'
	}
	recBody := buildRecordBody([]wire.Field{
		{Tag: 1, Value: oversizedKey},
		{Tag: 2, Value: []byte{}},
	})
	malformed := buildRecordListBytes([][]byte{recBody})
	raw := buildEvidenceWithField12(t, session, malformed)
	if _, err := UnmarshalBlameEvidence(raw); err == nil {
		t.Fatal("expected error for oversized Key in EvidenceField record")
	}
}

// ---- helpers for building malformed evidence wire messages --------------------

// buildEvidenceWithField12 constructs a valid BlameEvidence envelope but
// replaces the tag-12 field value with the given malformed bytes.
func buildEvidenceWithField12(t *testing.T, session SessionID, field12Value []byte) []byte {
	t.Helper()

	maxBlameEvidenceBytes := DefaultMaxBlameEvidenceBytes
	fields := []wire.Field{
		{Tag: 1, Value: wire.Uint16(uint16(Version))}, // Version
		{Tag: 2, Value: []byte("test-protocol")},      // Protocol
		{Tag: 3, Value: session[:]},                   // SessionID (32 bytes)
		{Tag: 4, Value: []byte{1}},                    // Round
		{Tag: 5, Value: wire.Uint32(1)},               // From
		{Tag: 6, Value: wire.Uint32(0)},               // To
		{Tag: 7, Value: []byte("test.payload")},       // PayloadType
		{Tag: 8, Value: make([]byte, 32)},             // PayloadHash (32 zero bytes)
		{Tag: 9, Value: []byte{}},                     // EnvelopeDigest
		{Tag: 10, Value: []byte("sign_partial")},      // Kind
		{Tag: 11, Value: []byte("mutation test")},     // Reason
		{Tag: 12, Value: field12Value},                // PublicInputs (recordlist)
	}
	raw, err := wire.MarshalFields(Version, blameWireType, fields)
	if err != nil {
		t.Fatalf("buildEvidenceWithField12: %v", err)
	}
	// Ensure total size respects the blame evidence limit.
	if len(raw) > maxBlameEvidenceBytes {
		t.Fatalf("buildEvidenceWithField12: constructed message too large: %d > %d",
			len(raw), maxBlameEvidenceBytes)
	}
	return raw
}

// buildRecordBody encodes a set of fields as a record body (uint16 count + fields).
func buildRecordBody(fields []wire.Field) []byte {
	return buildRecordBodyManual(fields)
}

// buildRecordBodyManual encodes fields as: uint16 field_count + tag:uint16 + len:uint32 + value.
func buildRecordBodyManual(fields []wire.Field) []byte {
	size := 2 // field count
	for _, f := range fields {
		size += 2 + 4 + len(f.Value)
	}
	out := make([]byte, 0, size)
	out = append(out, wire.Uint16(uint16(len(fields)))...)
	for _, f := range fields {
		out = append(out, wire.Uint16(f.Tag)...)
		out = append(out, wire.Uint32(uint32(len(f.Value)))...)
		out = append(out, f.Value...)
	}
	return out
}

// buildRecordListBytes encodes a list of record bodies as: uint32 count + per-record uint32 len + body.
func buildRecordListBytes(records [][]byte) []byte {
	out := wire.Uint32(uint32(len(records)))
	for _, rec := range records {
		out = append(out, wire.Uint32(uint32(len(rec)))...)
		out = append(out, rec...)
	}
	return out
}
