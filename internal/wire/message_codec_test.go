package wire

import (
	"bytes"
	"strings"
	"testing"
)

func TestMessageCodecRoundTripScenarios(t *testing.T) {
	t.Parallel()

	t.Run("struct value", func(t *testing.T) {
		t.Parallel()

		orig := simpleMessage{
			Name:  "hello",
			Count: 42,
			Data:  []byte{1, 2, 3},
		}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded simpleMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Name != orig.Name || decoded.Count != orig.Count || !bytes.Equal(decoded.Data, orig.Data) {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	})

	t.Run("struct pointer", func(t *testing.T) {
		t.Parallel()

		orig := &simpleMessage{
			Name:  "world",
			Count: 99,
			Data:  []byte{4, 5, 6},
		}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded simpleMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Name != orig.Name || decoded.Count != orig.Count || !bytes.Equal(decoded.Data, orig.Data) {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	})

	t.Run("pointer receiver message", func(t *testing.T) {
		t.Parallel()

		orig := &ptrMethodMessage{Value: 7}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded ptrMethodMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Value != 7 {
			t.Fatalf("got %d, want 7", decoded.Value)
		}
	})

	t.Run("nil bytes encodes empty", func(t *testing.T) {
		t.Parallel()

		orig := emptyBytesMessage{Data: nil}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded emptyBytesMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMessageMarshalCanonicalRemarshal(t *testing.T) {
	t.Parallel()

	orig := simpleMessage{Name: "x", Count: 1, Data: []byte{0xff}}
	raw1, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("marshal is not deterministic")
	}
}

func TestMessageRejectsInvalidObjectInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "wrong type id",
			run: func() error {
				raw, err := Marshal(simpleMessage{Name: "x", Count: 1})
				if err != nil {
					return err
				}
				var dst ptrMethodMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "wrong version",
			run: func() error {
				raw, err := MarshalFields(99, "test.ptrmethod", []Field{{Tag: 1, Value: Uint16(99)}})
				if err != nil {
					return err
				}
				var dst ptrMethodMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "missing field",
			run: func() error {
				raw, err := MarshalFields(1, "test.simple", []Field{{Tag: 1, Value: []byte("x")}})
				if err != nil {
					return err
				}
				var dst simpleMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "extra field",
			run: func() error {
				fields := []Field{
					{Tag: 1, Value: []byte("x")},
					{Tag: 2, Value: Uint32(1)},
					{Tag: 3, Value: []byte{}},
					{Tag: 99, Value: []byte("extra")},
				}
				raw, err := MarshalFields(1, "test.simple", fields)
				if err != nil {
					return err
				}
				var dst simpleMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "nil unmarshal destination",
			run: func() error {
				var dst *simpleMessage
				return Unmarshal([]byte("junk"), dst)
			},
		},
		{
			name: "marshal nil pointer",
			run: func() error {
				var m *simpleMessage
				_, err := Marshal(m)
				return err
			},
		},
		{
			name: "marshal non struct",
			run: func() error {
				_, err := Marshal(42)
				return err
			},
		},
		{
			name: "unmarshal non pointer",
			run: func() error {
				var dst simpleMessage
				return Unmarshal(nil, dst)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.run(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestMessageFieldConstraintScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "fixed length accepts exact size",
			run: func(t *testing.T) error {
				raw, err := Marshal(fixedLenMessage{Hash: make([]byte, 32)})
				if err != nil {
					return err
				}
				var decoded fixedLenMessage
				return Unmarshal(raw, &decoded)
			},
		},
		{
			name: "fixed length rejects wrong size on marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(fixedLenMessage{Hash: make([]byte, 31)})
				return err
			},
		},
		{
			name: "fixed length rejects wrong size on decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.fixedlen", []Field{{Tag: 1, Value: make([]byte, 31)}})
				if err != nil {
					return err
				}
				var decoded fixedLenMessage
				return Unmarshal(raw, &decoded)
			},
		},
		{
			name: "max bytes rejects oversized marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(maxBytesMessage{Payload: []byte("hello")}, WithFieldLimitsForMarshal(FieldLimits{"field": 3}))
				return err
			},
		},
		{
			name: "max bytes rejects oversized decode",
			run: func(t *testing.T) error {
				raw, err := Marshal(maxBytesMessage{Payload: []byte("hello")}, WithFieldLimitsForMarshal(FieldLimits{"field": 100}))
				if err != nil {
					return err
				}
				var decoded maxBytesMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 3}))
			},
		},
		{
			name: "max bytes accepts under limit",
			run: func(t *testing.T) error {
				raw, err := Marshal(maxBytesMessage{Payload: []byte("hi")}, WithFieldLimitsForMarshal(FieldLimits{"field": 10}))
				if err != nil {
					return err
				}
				var decoded maxBytesMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 10}))
			},
		},
		{
			name: "missing limit name rejects",
			run: func(t *testing.T) error {
				raw, err := Marshal(maxBytesMessage{Payload: []byte("hi")}, WithFieldLimitsForMarshal(FieldLimits{"field": 10}))
				if err != nil {
					return err
				}
				var decoded maxBytesMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"other": 100}))
			},
		},
		{
			name: "nonpositive limit rejects marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(maxBytesMessage{}, WithFieldLimitsForMarshal(FieldLimits{"field": 0}))
				return err
			},
		},
		{
			name: "nonpositive limit rejects decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.maxbytes", []Field{{Tag: 1, Value: []byte{}}})
				if err != nil {
					return err
				}
				var decoded maxBytesMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 0}))
			},
		},
		{
			name: "malformed u8 rejects",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.nested", []Field{{Tag: 1, Value: []byte{0xff, 0xff}}})
				if err != nil {
					return err
				}
				var dst nestedMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "invalid utf8 rejects first form",
			run: func(t *testing.T) error {
				fields := []Field{
					{Tag: 1, Value: []byte{0xff, 0xfe, 0xfd}},
					{Tag: 2, Value: Uint32(1)},
					{Tag: 3, Value: []byte{}},
				}
				raw, err := MarshalFields(1, "test.simple", fields)
				if err != nil {
					return err
				}
				var dst simpleMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "invalid utf8 rejects continuation byte",
			run: func(t *testing.T) error {
				fields := []Field{
					{Tag: 1, Value: []byte{0x80}},
					{Tag: 2, Value: Uint32(0)},
					{Tag: 3, Value: []byte{}},
				}
				raw, err := MarshalFields(1, "test.simple", fields)
				if err != nil {
					return err
				}
				var dst simpleMessage
				return Unmarshal(raw, &dst)
			},
		},
		{
			name: "max_bits rejects oversized bigpos decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.bigpos.maxbits", []Field{{Tag: 1, Value: []byte{0xAB, 0xCD}}})
				if err != nil {
					return err
				}
				var decoded bigPosMaxBitsMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 8}))
			},
		},
		{
			name: "max_bits accepts under-limit bigpos decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.bigpos.maxbits", []Field{{Tag: 1, Value: []byte{0xAB, 0xCD}}})
				if err != nil {
					return err
				}
				var decoded bigPosMaxBitsMessage
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 1000}))
			},
		},
		{
			name: "max_bits missing limit name rejects",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.bigpos.maxbits", []Field{{Tag: 1, Value: []byte{0xAB, 0xCD}}})
				if err != nil {
					return err
				}
				var decoded bigPosMaxBitsMessage
				// "other" does not match the "limit" name in the wire tag.
				return Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"other": 1000}))
			},
		},
	}

	wantErr := map[string]bool{
		"fixed length rejects wrong size on marshal": true,
		"fixed length rejects wrong size on decode":  true,
		"max bytes rejects oversized marshal":        true,
		"max bytes rejects oversized decode":         true,
		"missing limit name rejects":                 true,
		"nonpositive limit rejects marshal":          true,
		"nonpositive limit rejects decode":           true,
		"max_bits rejects oversized bigpos decode":   true,
		"max_bits accepts under-limit bigpos decode": false,
		"max_bits missing limit name rejects":        true,
		"malformed u8 rejects":                       true,
		"invalid utf8 rejects first form":            true,
		"invalid utf8 rejects continuation byte":     true,
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.run(t)
			if wantErr[tc.name] {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMessageBoolEncodeDecode(t *testing.T) {
	t.Parallel()

	for _, v := range []bool{true, false} {
		t.Run(func() string {
			if v {
				return "true"
			}
			return "false"
		}(), func(t *testing.T) {
			t.Parallel()

			raw, err := Marshal(boolMessage{Flag: v})
			if err != nil {
				t.Fatal(err)
			}
			var decoded boolMessage
			if err := Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Flag != v {
				t.Fatalf("got %v, want %v", decoded.Flag, v)
			}
		})
	}
}

func TestMessageCompoundRoundTrips(t *testing.T) {
	t.Parallel()

	t.Run("u32 list", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(u32ListMessage{IDs: []uint32{1, 2, 3}}, WithFieldLimitsForMarshal(FieldLimits{"ids": 10}))
		if err != nil {
			t.Fatal(err)
		}
		var decoded u32ListMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"ids": 10})); err != nil {
			t.Fatal(err)
		}
		if len(decoded.IDs) != 3 || decoded.IDs[0] != 1 || decoded.IDs[2] != 3 {
			t.Fatalf("u32list mismatch: %v", decoded.IDs)
		}
	})

	t.Run("bytes list", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bytesListMessage{Items: [][]byte{{1, 2}, {3, 4, 5}}}, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded bytesListMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 100, "items": 10})); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Items) != 2 || !bytes.Equal(decoded.Items[1], []byte{3, 4, 5}) {
			t.Fatalf("byteslist mismatch: %v", decoded.Items)
		}
	})

	t.Run("nil bytes list", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bytesListMessage{Items: nil}, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded bytesListMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 100, "items": 10})); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Items) != 0 {
			t.Fatalf("nil byteslist round-trip: got %d items", len(decoded.Items))
		}
	})

	t.Run("party bytes", func(t *testing.T) {
		t.Parallel()

		orig := partyBytesMessage{
			Records: []PartyBytes[uint32]{
				{Party: 1, Bytes: []byte("aaa")},
				{Party: 3, Bytes: []byte("bbb")},
			},
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded partyBytesMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 100})); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Records) != 2 {
			t.Fatalf("partybytes count: %d", len(decoded.Records))
		}
		if decoded.Records[0].Party != 1 || !bytes.Equal(decoded.Records[0].Bytes, []byte("aaa")) {
			t.Fatalf("partybytes[0]: party=%d bytes=%x", decoded.Records[0].Party, decoded.Records[0].Bytes)
		}
	})

	t.Run("empty party bytes", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(partyBytesMessage{}, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded partyBytesMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 100})); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Records) != 0 {
			t.Fatalf("empty partybytes: got %d records", len(decoded.Records))
		}
	})

	t.Run("party byte pairs", func(t *testing.T) {
		t.Parallel()

		orig := partyBytePairsMessage{
			Pairs: []PartyBytePair[uint32]{
				{Party: 1, First: []byte{1}, Second: []byte{2}},
				{Party: 2, First: []byte{3}, Second: []byte{4}},
			},
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}
		var decoded partyBytePairsMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 100})); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Pairs) != 2 {
			t.Fatalf("partybytepairs count: %d", len(decoded.Pairs))
		}
		if !bytes.Equal(decoded.Pairs[1].First, []byte{3}) {
			t.Fatalf("partybytepairs[1].First: %x", decoded.Pairs[1].First)
		}
	})

	t.Run("nested", func(t *testing.T) {
		t.Parallel()

		orig := nestedMessage{
			Inner: simpleMessage{Name: "nested", Count: 7, Data: []byte{9}},
			Tag:   42,
		}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var decoded nestedMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Inner.Name != "nested" || decoded.Inner.Count != 7 || decoded.Tag != 42 {
			t.Fatalf("nested mismatch: %+v", decoded)
		}
	})

	t.Run("nested propagates field limits", func(t *testing.T) {
		t.Parallel()

		orig := nestedLimitMessage{
			Inner: nestedLimitInnerMessage{Payload: []byte("ok")},
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{"field": 4}))
		if err != nil {
			t.Fatal(err)
		}
		var decoded nestedLimitMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 4})); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Inner.Payload, orig.Inner.Payload) {
			t.Fatalf("nested payload mismatch: %x", decoded.Inner.Payload)
		}
	})
}

func TestMessageCompoundRejectsLimits(t *testing.T) {
	t.Parallel()

	if _, err := Marshal(u32ListMessage{IDs: []uint32{1, 2, 3, 4, 5}}, WithFieldLimitsForMarshal(FieldLimits{"ids": 3})); err == nil {
		t.Fatal("expected marshal error for too many u32list items")
	}
	if _, err := Marshal(intU32ListMessage{IDs: []int{-1}}); err == nil {
		t.Fatal("expected marshal error for negative u32list item")
	}

	raw, err := Marshal(u32ListMessage{IDs: []uint32{1, 2, 3, 4, 5}}, WithFieldLimitsForMarshal(FieldLimits{"ids": 10}))
	if err != nil {
		t.Fatal(err)
	}
	var decoded u32ListMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"ids": 3})); err == nil {
		t.Fatal("expected error for too many items")
	}
}

func TestMessageNestedRejectsLimitViolations(t *testing.T) {
	t.Parallel()

	if _, err := Marshal(nestedLimitMessage{
		Inner: nestedLimitInnerMessage{Payload: []byte("too long")},
	}, WithFieldLimitsForMarshal(FieldLimits{"field": 3})); err == nil {
		t.Fatal("expected nested marshal to enforce field limit")
	}

	innerRaw, err := MarshalFields(1, "test.nestedlimit.inner", []Field{{Tag: 1, Value: []byte("too long")}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalFields(1, "test.nestedlimit", []Field{{Tag: 1, Value: innerRaw}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded nestedLimitMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"field": 3})); err == nil {
		t.Fatal("expected nested decode to enforce field limit")
	}
}

func TestMessageValidateAndHooks(t *testing.T) {
	t.Parallel()

	t.Run("validate called on marshal", func(t *testing.T) {
		t.Parallel()

		m := validatedMessage{Value: []byte{1}, ok: false}
		if _, err := Marshal(&m); err == nil {
			t.Fatal("expected validation error on marshal")
		}
		m.ok = true
		if _, err := Marshal(&m); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("validate called on unmarshal", func(t *testing.T) {
		t.Parallel()

		m := validatedMessage{Value: []byte{1}, ok: true}
		raw, err := Marshal(&m)
		if err != nil {
			t.Fatal(err)
		}
		decoded := validatedMessage{Value: []byte{9}}
		if err := Unmarshal(raw, &decoded); err == nil {
			t.Fatal("expected validation error on unmarshal")
		}
		if !bytes.Equal(decoded.Value, []byte{9}) {
			t.Fatalf("failed unmarshal mutated destination to %x", decoded.Value)
		}
	})

	t.Run("hooks called", func(t *testing.T) {
		t.Parallel()

		m := hookMessage{Value: 5}
		raw, err := Marshal(&m)
		if err != nil {
			t.Fatal(err)
		}
		if !m.BeforeCalled {
			t.Fatal("BeforeMarshalWire not called")
		}

		var decoded hookMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if !decoded.AfterCalled {
			t.Fatal("AfterUnmarshalWire not called")
		}
		if decoded.Value != 5 {
			t.Fatalf("value mismatch: %d", decoded.Value)
		}
	})
}

func TestMessageWireTypeAndVersion(t *testing.T) {
	t.Parallel()

	var m Message = &ptrMethodMessage{}
	if m.WireType() != "test.ptrmethod" || m.WireVersion() != 2 {
		t.Fatalf("Message: type=%s version=%d", m.WireType(), m.WireVersion())
	}
}

func TestMessageErrorWrappingIncludesFieldContext(t *testing.T) {
	t.Parallel()

	fields := []Field{
		{Tag: 1, Value: []byte{}},
		{Tag: 2, Value: Uint32(0)},
	}
	raw, err := MarshalFields(1, "test.custom.multifield", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customMultiFieldMessage
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "First") || !strings.Contains(err.Error(), "tag 1") {
		t.Fatalf("error should mention field name and tag: %v", err)
	}
}
