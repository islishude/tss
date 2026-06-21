package wire

import (
	"bytes"
	"reflect"
	"strings"
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

func TestCustomFieldMaxItems(t *testing.T) {
	t.Parallel()

	t.Run("marshal and decode within limit", func(t *testing.T) {
		t.Parallel()

		limits := FieldLimits{"items": 2}
		orig := customMaxItemsMessage{
			Data: customCountedList{items: [][]byte{{1}, {2}}},
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
		if err != nil {
			t.Fatal(err)
		}

		var decoded customMaxItemsMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Data.items) != 2 ||
			!bytes.Equal(decoded.Data.items[0], []byte{1}) ||
			!bytes.Equal(decoded.Data.items[1], []byte{2}) {
			t.Fatalf("decoded items mismatch: %x", decoded.Data.items)
		}
	})

	t.Run("marshal rejects count over field limit", func(t *testing.T) {
		t.Parallel()

		_, err := Marshal(
			customMaxItemsMessage{
				Data: customCountedList{items: [][]byte{{1}, {2}, {3}}},
			},
			WithFieldLimitsForMarshal(FieldLimits{"items": 2}),
		)
		if err == nil {
			t.Fatal("expected max_items error")
		}
		if !strings.Contains(err.Error(), "custom item count") ||
			!strings.Contains(err.Error(), "exceeds max_items") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("decode rejects count before custom unmarshal", func(t *testing.T) {
		t.Parallel()

		raw, err := MarshalFields(
			1,
			"test.custom.maxitems.panic",
			[]Field{{Tag: 1, Value: EncodeBytesList([][]byte{{1}, {2}, {3}})}},
		)
		if err != nil {
			t.Fatal(err)
		}
		var decoded panicCustomMaxItemsMessage
		err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"items": 2}))
		if err == nil {
			t.Fatal("expected max_items error")
		}
		if !strings.Contains(err.Error(), "custom item count") ||
			!strings.Contains(err.Error(), "exceeds max_items") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("decode rejects malformed count prefix", func(t *testing.T) {
		t.Parallel()

		raw, err := MarshalFields(
			1,
			"test.custom.maxitems",
			[]Field{{Tag: 1, Value: []byte{1, 2}}},
		)
		if err != nil {
			t.Fatal(err)
		}
		var decoded customMaxItemsMessage
		err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"items": 2}))
		if err == nil {
			t.Fatal("expected malformed count error")
		}
		if !strings.Contains(err.Error(), "custom item count") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("custom without max_items remains opaque", func(t *testing.T) {
		t.Parallel()

		raw, err := MarshalFields(
			1,
			"test.custom.valrecv",
			[]Field{{Tag: 1, Value: []byte{1, 2}}},
		)
		if err != nil {
			t.Fatal(err)
		}
		var decoded customValueReceiverMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Data.raw, []byte{1, 2}) {
			t.Fatalf("decoded raw mismatch: %x", decoded.Data.raw)
		}
	})

	t.Run("optional custom may be absent without limits", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(optionalCustomMaxItemsMessage{})
		if err != nil {
			t.Fatal(err)
		}
		var decoded optionalCustomMaxItemsMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Data != nil {
			t.Fatal("absent optional custom field decoded as present")
		}
	})

	t.Run("optional custom present still enforces limit", func(t *testing.T) {
		t.Parallel()

		raw, err := MarshalFields(
			1,
			"test.custom.maxitems.optional",
			[]Field{{Tag: 1, Value: EncodeBytesList([][]byte{{1}, {2}, {3}})}},
		)
		if err != nil {
			t.Fatal(err)
		}
		var decoded optionalCustomMaxItemsMessage
		err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"items": 2}))
		if err == nil {
			t.Fatal("expected max_items error")
		}
		if !strings.Contains(err.Error(), "custom item count") ||
			!strings.Contains(err.Error(), "exceeds max_items") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCustomFieldMaxItemsRejectsGlobalCount(t *testing.T) {
	t.Parallel()

	count := uint32(maxRecordCount + 1)
	limits := FieldLimits{"items": maxRecordCount + 2}

	_, err := Marshal(
		rawCustomMaxItemsMessage{Data: customBytes{raw: Uint32(count)}},
		WithFieldLimitsForMarshal(limits),
	)
	if err == nil {
		t.Fatal("marshal accepted custom count over global limit")
	}
	if !strings.Contains(err.Error(), "custom item count") ||
		!strings.Contains(err.Error(), "exceeds global limit") {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	raw, err := MarshalFields(
		1,
		"test.custom.maxitems.panic",
		[]Field{{Tag: 1, Value: Uint32(count)}},
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded panicCustomMaxItemsMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(limits))
	if err == nil {
		t.Fatal("decode accepted custom count over global limit")
	}
	if !strings.Contains(err.Error(), "custom item count") ||
		!strings.Contains(err.Error(), "exceeds global limit") {
		t.Fatalf("unexpected decode error: %v", err)
	}
}

func TestCustomListRoundTripScenarios(t *testing.T) {
	t.Parallel()

	t.Run("value items", func(t *testing.T) {
		t.Parallel()

		orig := customListMessage{
			Items: []customBytes{
				{raw: []byte{1, 2}},
				{raw: []byte{3, 4, 5}},
			},
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded customListMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits())); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Items) != 2 ||
			!bytes.Equal(decoded.Items[0].raw, []byte{1, 2}) ||
			!bytes.Equal(decoded.Items[1].raw, []byte{3, 4, 5}) {
			t.Fatalf("decoded customlist mismatch: %+v", decoded.Items)
		}
	})

	t.Run("pointer items", func(t *testing.T) {
		t.Parallel()

		orig := customPointerListMessage{
			Items: []*customBytes{
				{raw: []byte{6, 7}},
				{raw: []byte{8, 9}},
			},
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded customPointerListMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits())); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Items) != 2 || decoded.Items[0] == nil || decoded.Items[1] == nil ||
			!bytes.Equal(decoded.Items[0].raw, []byte{6, 7}) ||
			!bytes.Equal(decoded.Items[1].raw, []byte{8, 9}) {
			t.Fatalf("decoded pointer customlist mismatch: %+v", decoded.Items)
		}
	})
}

func TestCustomListRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "nil pointer item on marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(customPointerListMessage{
					Items: []*customBytes{{raw: []byte{1}}, nil},
				}, WithFieldLimitsForMarshal(testFieldLimits()))
				return err
			},
		},
		{
			name: "nil item bytes on marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(customListNilReturnMessage{
					Items: []customNilReturn{{}},
				})
				return err
			},
		},
		{
			name: "malformed item on decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.customlist", []Field{
					{Tag: 1, Value: EncodeBytesList([][]byte{{}})},
				})
				if err != nil {
					return err
				}
				var decoded customListMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits()))
			},
		},
		{
			name: "fixed length mismatch",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.customlist.fixedlen", []Field{
					{Tag: 1, Value: EncodeBytesList([][]byte{{1}})},
				})
				if err != nil {
					return err
				}
				var decoded customListFixedLenMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits()))
			},
		},
		{
			name: "max bytes exceeded",
			run: func(t *testing.T) error {
				raw, err := Marshal(
					customListMessage{Items: []customBytes{{raw: []byte{1, 2, 3}}}},
					WithFieldLimitsForMarshal(FieldLimits{"items": 2, "field": 10}),
				)
				if err != nil {
					return err
				}
				var decoded customListMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"items": 2, "field": 2}))
			},
		},
		{
			name: "max items exceeded",
			run: func(t *testing.T) error {
				_, err := Marshal(
					customListMessage{Items: []customBytes{{raw: []byte{1}}, {raw: []byte{2}}, {raw: []byte{3}}}},
					WithFieldLimitsForMarshal(FieldLimits{"items": 2, "field": 10}),
				)
				return err
			},
		},
		{
			name: "trailing bytes",
			run: func(t *testing.T) error {
				body := EncodeBytesList([][]byte{{1, 2}})
				body = append(body, 0xff)
				raw, err := MarshalFields(1, "test.customlist", []Field{{Tag: 1, Value: body}})
				if err != nil {
					return err
				}
				var decoded customListMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits()))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.run(t); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCustomListCanonicalBytesMatchBytesListFormat(t *testing.T) {
	t.Parallel()

	orig := customListMessage{
		Items: []customBytes{
			{raw: []byte{1, 2}},
			{raw: []byte{3, 4, 5}},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	_, fields, err := UnmarshalFields(raw, "test.customlist")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fields[0].Value, EncodeBytesList([][]byte{{1, 2}, {3, 4, 5}}); !bytes.Equal(got, want) {
		t.Fatalf("customlist bytes = %x, want %x", got, want)
	}
}

func TestCustomListSchemaRejectsInvalidTypes(t *testing.T) {
	t.Parallel()

	tests := []reflect.Type{
		reflect.TypeFor[struct {
			Item customBytes `wire:"1,customlist"`
		}](),
		reflect.TypeFor[struct {
			Items []customNoMarshal `wire:"1,customlist"`
		}](),
		reflect.TypeFor[struct {
			Items []customNoUnmarshal `wire:"1,customlist"`
		}](),
	}
	for _, typ := range tests {
		if _, err := getSchema(typ); err == nil {
			t.Fatalf("accepted invalid customlist schema %s", typ)
		}
	}
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
