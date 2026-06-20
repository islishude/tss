package wire

import "testing"

type recordValueHelperRecord struct {
	ID   uint32 `wire:"1,u32"`
	Data []byte `wire:"2,bytes,max_bytes=field"`
}

func TestMarshalRecordValueRoundTrip(t *testing.T) {
	t.Parallel()

	limits := FieldLimits{"field": 8}
	raw, err := MarshalRecordValue(
		recordValueHelperRecord{ID: 7, Data: []byte{1, 2, 3}},
		WithFieldLimitsForMarshal(limits),
	)
	if err != nil {
		t.Fatalf("MarshalRecordValue: %v", err)
	}

	var decoded recordValueHelperRecord
	if err := UnmarshalRecordValue(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatalf("UnmarshalRecordValue: %v", err)
	}
	if decoded.ID != 7 || string(decoded.Data) != string([]byte{1, 2, 3}) {
		t.Fatalf("decoded mismatch: %+v", decoded)
	}
}

func TestRecordValueHelpersEnforceLimits(t *testing.T) {
	t.Parallel()

	if _, err := MarshalRecordValue(
		recordValueHelperRecord{ID: 7, Data: []byte{1, 2, 3}},
		WithFieldLimitsForMarshal(FieldLimits{"field": 2}),
	); err == nil {
		t.Fatal("MarshalRecordValue accepted oversized field")
	}

	raw, err := MarshalRecordValue(
		recordValueHelperRecord{ID: 7, Data: []byte{1, 2, 3}},
		WithFieldLimitsForMarshal(FieldLimits{"field": 8}),
	)
	if err != nil {
		t.Fatalf("MarshalRecordValue setup: %v", err)
	}
	var decoded recordValueHelperRecord
	if err := UnmarshalRecordValue(raw, &decoded, WithFieldLimits(FieldLimits{"field": 2})); err == nil {
		t.Fatal("UnmarshalRecordValue accepted oversized field")
	}
}

func TestRecordFieldHelpersRejectTrailingData(t *testing.T) {
	t.Parallel()

	raw, err := MarshalRecordFields([]Field{{Tag: 1, Value: []byte{7}}})
	if err != nil {
		t.Fatalf("MarshalRecordFields: %v", err)
	}
	raw = append(raw, 0)
	if _, err := UnmarshalRecordFieldsWithLimits(raw, DefaultFrameLimits(), "test.record"); err == nil {
		t.Fatal("UnmarshalRecordFieldsWithLimits accepted trailing data")
	}
}

func TestResolveDirectCodecOptions(t *testing.T) {
	t.Parallel()

	marshalLimits := FieldLimits{"field": 7}
	marshalOptions := ResolveMarshalOptions(WithFieldLimitsForMarshal(marshalLimits))
	if marshalOptions.FieldLimits["field"] != 7 {
		t.Fatalf("marshal field limit = %d, want 7", marshalOptions.FieldLimits["field"])
	}

	frameLimits := FrameLimits{MaxTotalBytes: 11, MaxFields: 2, MaxFieldBytes: 3}
	unmarshalLimits := FieldLimits{"field": 5}
	unmarshalOptions := ResolveUnmarshalOptions(
		WithFrameLimits(frameLimits),
		WithFieldLimits(unmarshalLimits),
	)
	if unmarshalOptions.FrameLimits != frameLimits {
		t.Fatalf("unmarshal frame limits = %+v, want %+v", unmarshalOptions.FrameLimits, frameLimits)
	}
	if unmarshalOptions.FieldLimits["field"] != 5 {
		t.Fatalf("unmarshal field limit = %d, want 5", unmarshalOptions.FieldLimits["field"])
	}

	defaults := ResolveUnmarshalOptions()
	if defaults.FrameLimits != DefaultFrameLimits() {
		t.Fatalf("default frame limits = %+v, want %+v", defaults.FrameLimits, DefaultFrameLimits())
	}
}

func TestUnmarshalMessageBodyAppliesOptions(t *testing.T) {
	t.Parallel()

	msg := msgHookDTO{Value: 7}
	raw, err := Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalMessageBody(raw, msg, WithFrameLimits(FrameLimits{
		MaxTotalBytes: len(raw) - 1,
		MaxFields:     8,
		MaxFieldBytes: 8,
	})); err == nil {
		t.Fatal("UnmarshalMessageBody ignored caller frame limit")
	}
	fields, err := UnmarshalMessageBody(raw, msg, WithFrameLimits(FrameLimits{
		MaxTotalBytes: len(raw),
		MaxFields:     1,
		MaxFieldBytes: 2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[0].Tag != 1 {
		t.Fatalf("unexpected fields: %+v", fields)
	}
}
