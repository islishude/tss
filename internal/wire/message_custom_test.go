package wire

import (
	"bytes"
	"testing"
)

func TestCustomFieldRoundTripScenarios(t *testing.T) {
	t.Parallel()

	t.Run("value receiver", func(t *testing.T) {
		t.Parallel()

		orig := customValueReceiverMessage{
			Data: customBytes{raw: []byte{1, 2, 3, 4}},
		}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded customValueReceiverMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Data.raw, []byte{1, 2, 3, 4}) {
			t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
		}
	})

	t.Run("pointer receiver", func(t *testing.T) {
		t.Parallel()

		orig := customPointerReceiverMessage{
			Data: customPtrBytes{raw: []byte{5, 6, 7, 8}},
		}
		raw, err := Marshal(&orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded customPointerReceiverMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Data.raw, []byte{5, 6, 7, 8}) {
			t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
		}
	})

	t.Run("pointer field auto alloc", func(t *testing.T) {
		t.Parallel()

		orig := customPointerFieldMessage{
			Data: &customBytes{raw: []byte{9, 9, 9, 9}},
		}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded customPointerFieldMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Data == nil {
			t.Fatal("pointer field was not auto-allocated")
		}
		if !bytes.Equal(decoded.Data.raw, []byte{9, 9, 9, 9}) {
			t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
		}
	})

	t.Run("pointer receiver method through addressable value", func(t *testing.T) {
		t.Parallel()

		orig := customPointerReceiverMessage{
			Data: customPtrBytes{raw: []byte{10, 20}},
		}
		raw, err := Marshal(&orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded customPointerReceiverMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Data.raw, []byte{10, 20}) {
			t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
		}
	})
}

func TestCustomFieldRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "nil pointer field on marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(customPointerFieldMessage{Data: nil})
				return err
			},
		},
		{
			name: "missing MarshalWireValue",
			run: func(t *testing.T) error {
				_, err := Marshal(customNoMarshalMessage{})
				return err
			},
		},
		{
			name: "missing UnmarshalWireValue",
			run: func(t *testing.T) error {
				raw, err := Marshal(customNoUnmarshalMessage{Data: customNoUnmarshal{raw: []byte{1}}})
				if err != nil {
					return err
				}
				var decoded customNoUnmarshalMessage
				return Unmarshal(raw, &decoded)
			},
		},
		{
			name: "MarshalWireValue returns nil",
			run: func(t *testing.T) error {
				_, err := Marshal(customNilReturnMessage{})
				return err
			},
		},
		{
			name: "wrong fixed length",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.custom.fixedlen", []Field{{Tag: 1, Value: make([]byte, 16)}})
				if err != nil {
					return err
				}
				var decoded customFixedLenMessage
				return Unmarshal(raw, &decoded)
			},
		},
		{
			name: "oversized max bytes",
			run: func(t *testing.T) error {
				raw, err := Marshal(customMaxBytesMessage{Data: customBytes{raw: []byte("hello")}}, WithFieldLimitsForMarshal(testFieldLimits()))
				if err != nil {
					return err
				}
				var decoded customMaxBytesMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 3}))
			},
		},
		{
			name: "missing named max bytes limit",
			run: func(t *testing.T) error {
				raw, err := Marshal(customMaxBytesMessage{Data: customBytes{raw: []byte("hi")}}, WithFieldLimitsForMarshal(testFieldLimits()))
				if err != nil {
					return err
				}
				var decoded customMaxBytesMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"other": 100}))
			},
		},
		{
			name: "extra tag",
			run: func(t *testing.T) error {
				fields := []Field{
					{Tag: 1, Value: []byte{1}},
					{Tag: 2, Value: Uint32(42)},
					{Tag: 3, Value: []byte("extra")},
				}
				raw, err := MarshalFields(1, "test.custom.multifield", fields)
				if err != nil {
					return err
				}
				var decoded customMultiFieldMessage
				return Unmarshal(raw, &decoded)
			},
		},
		{
			name: "missing tag",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.custom.multifield", []Field{{Tag: 1, Value: []byte{1}}})
				if err != nil {
					return err
				}
				var decoded customMultiFieldMessage
				return Unmarshal(raw, &decoded)
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.run(t); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCustomFieldConstraintSuccessScenarios(t *testing.T) {
	t.Parallel()

	t.Run("fixed length accepts exact size", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(customFixedLenMessage{Data: customBytes{raw: make([]byte, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		var decoded customFixedLenMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("max bytes accepts adequate limit", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(customMaxBytesMessage{Data: customBytes{raw: []byte("hello")}}, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded customMaxBytesMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 10})); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCustomFieldOrdering(t *testing.T) {
	t.Parallel()

	orig := customMultiFieldMessage{
		First:  customBytes{raw: []byte{1, 2}},
		Second: 42,
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customMultiFieldMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.First.raw, []byte{1, 2}) || decoded.Second != 42 {
		t.Fatalf("field ordering broken: First=%x Second=%d", decoded.First.raw, decoded.Second)
	}
}

func FuzzCustomField(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, in []byte) {
		fields := []Field{
			{Tag: 1, Value: in},
		}
		raw, err := MarshalFields(1, "test.custom.valrecv", fields)
		if err != nil {
			t.Fatal(err)
		}
		var decoded customValueReceiverMessage
		_ = Unmarshal(raw, &decoded)
	})
}
