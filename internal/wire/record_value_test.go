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
