package wire

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"
)

type taggedUnexportedField struct {
	secret []byte `wire:"1,bytes"`
}

// TestLenMismatchWithArrayLength verifies that len=N is validated against
// the array length at schema parse time for bytes fields.
func TestLenMismatchWithArrayLength(t *testing.T) {
	t.Parallel()

	t.Run("reject mismatch", func(t *testing.T) {
		t.Parallel()

		type badLenArray struct {
			Val [8]byte `wire:"1,bytes,len=10"`
		}
		if _, err := getSchema(reflect.TypeFor[badLenArray]()); err == nil {
			t.Fatal("expected schema error for len=10 on [8]byte")
		}
	})

	t.Run("accept matching length", func(t *testing.T) {
		t.Parallel()

		type goodLenArray struct {
			Val [8]byte `wire:"1,bytes,len=8"`
		}
		if _, err := getSchema(reflect.TypeFor[goodLenArray]()); err != nil {
			t.Fatalf("unexpected error for len=8 on [8]byte: %v", err)
		}
	})

	t.Run("reject zero length", func(t *testing.T) {
		t.Parallel()

		type zeroLenBytes struct {
			Val []byte `wire:"1,bytes,len=0"`
		}
		if _, err := getSchema(reflect.TypeFor[zeroLenBytes]()); err == nil {
			t.Fatal("expected schema error for len=0")
		}
	})
}

func TestImplicitArrayLengthIsExact(t *testing.T) {
	t.Parallel()

	for _, value := range [][]byte{
		{1, 2, 3},
		{1, 2, 3, 4, 5},
	} {
		raw, err := MarshalFields(1, "test.implicitarray", []Field{{Tag: 1, Value: value}})
		if err != nil {
			t.Fatal(err)
		}
		var decoded implicitArrayMessage
		if err := Unmarshal(raw, &decoded); err == nil {
			t.Fatalf("accepted array value length %d", len(value))
		}
	}
}

func TestSchemaRejectsTaggedUnexportedField(t *testing.T) {
	t.Parallel()

	_ = taggedUnexportedField{}.secret
	if _, err := getSchema(reflect.TypeFor[taggedUnexportedField]()); err == nil {
		t.Fatal("expected tagged unexported field to be rejected")
	}
}

func TestFieldTagAcceptsPointerToStruct(t *testing.T) {
	t.Parallel()

	tag, err := FieldTag(&simpleMessage{}, "Name")
	if err != nil {
		t.Fatal(err)
	}
	if tag != 1 {
		t.Fatalf("tag = %d, want 1", tag)
	}
}

func TestSchemaRejectsOptionalPrimitivePointers(t *testing.T) {
	t.Parallel()

	tests := []reflect.Type{
		reflect.TypeFor[struct {
			Value *uint32 `wire:"1,optional"`
		}](),
		reflect.TypeFor[struct {
			Value *string `wire:"1,optional"`
		}](),
		reflect.TypeFor[struct {
			Value *[]byte `wire:"1,optional"`
		}](),
		reflect.TypeFor[struct {
			Value *bool `wire:"1,optional"`
		}](),
	}
	for _, typ := range tests {
		if _, err := getSchema(typ); err == nil {
			t.Fatalf("accepted optional primitive field in %s", typ)
		}
	}
}

func TestSchemaRejectsUnsupportedTagOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  reflect.Type
	}{
		{
			name: "max_bytes on u32",
			typ: reflect.TypeFor[struct {
				Count uint32 `wire:"1,u32,max_bytes=count"`
			}](),
		},
		{
			name: "max_bits on string",
			typ: reflect.TypeFor[struct {
				Name string `wire:"1,string,max_bits=name_bits"`
			}](),
		},
		{
			name: "max_items on bool",
			typ: reflect.TypeFor[struct {
				Flag bool `wire:"1,bool,max_items=flags"`
			}](),
		},
		{
			name: "len on u32list",
			typ: reflect.TypeFor[struct {
				IDs []uint32 `wire:"1,u32list,len=4"`
			}](),
		},
		{
			name: "max_bytes on record",
			typ: reflect.TypeFor[struct {
				Inner simpleMessage `wire:"1,record,max_bytes=inner"`
			}](),
		},
		{
			name: "max_bits on byteslist",
			typ: reflect.TypeFor[struct {
				Items [][]byte `wire:"1,byteslist,max_bits=item_bits"`
			}](),
		},
		{
			name: "max_bytes on fixed width map value",
			typ: reflect.TypeFor[struct {
				Items map[uint32]uint32 `wire:"1,map,max_bytes=item"`
			}](),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := getSchema(tc.typ); err == nil {
				t.Fatalf("accepted unsupported tag option in %s", tc.typ)
			}
		})
	}
}

func TestSchemaRejectsDuplicateTagOptions(t *testing.T) {
	t.Parallel()

	tests := []reflect.Type{
		reflect.TypeFor[struct {
			Hash []byte `wire:"1,bytes,len=32,len=64"`
		}](),
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,max_bytes=a,max_bytes=b"`
		}](),
		reflect.TypeFor[struct {
			IDs []uint32 `wire:"1,u32list,max_items=a,max_items=b"`
		}](),
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,max_bits=a,max_bits=b"`
		}](),
		reflect.TypeFor[struct {
			Inner *simpleMessage `wire:"1,record,optional,optional"`
		}](),
	}
	for _, typ := range tests {
		if _, err := getSchema(typ); err == nil {
			t.Fatalf("accepted duplicate tag option in %s", typ)
		}
	}
}

func TestSchemaRejectsInvalidLimitNames(t *testing.T) {
	t.Parallel()

	tests := []reflect.Type{
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,max_bytes="`
		}](),
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,max_bytes=Point"`
		}](),
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,max_bits=point-bits"`
		}](),
		reflect.TypeFor[struct {
			IDs []uint32 `wire:"1,u32list,max_items=1parties"`
		}](),
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,max_bytes=???"`
		}](),
	}
	for _, typ := range tests {
		if _, err := getSchema(typ); err == nil {
			t.Fatalf("accepted invalid limit name in %s", typ)
		}
	}
}

func TestSchemaAcceptsSupportedTagOptionMatrix(t *testing.T) {
	t.Parallel()

	tests := []reflect.Type{
		reflect.TypeFor[struct {
			Data []byte `wire:"1,bytes,len=32,max_bytes=field,max_bits=field_bits"`
		}](),
		reflect.TypeFor[struct {
			Name string `wire:"1,string,len=4,max_bytes=name"`
		}](),
		reflect.TypeFor[struct {
			Items [][]byte `wire:"1,byteslist,max_bytes=item,max_items=items"`
		}](),
		reflect.TypeFor[struct {
			Items []PartyBytes[uint32] `wire:"1,partybytes,max_bytes=item,max_items=items"`
		}](),
		reflect.TypeFor[struct {
			Inner *simpleMessage `wire:"1,nested,optional,max_bytes=inner"`
		}](),
		reflect.TypeFor[struct {
			Data customBytes `wire:"1,custom,len=2,max_bytes=field,max_items=items"`
		}](),
		reflect.TypeFor[struct {
			Items []customBytes `wire:"1,customlist,len=2,max_bytes=item,max_items=items"`
		}](),
		reflect.TypeFor[struct {
			Val *big.Int `wire:"1,bigpos,len=2,max_bytes=field,max_bits=field_bits,optional"`
		}](),
		reflect.TypeFor[struct {
			Items []simpleMessage `wire:"1,recordlist,max_items=items"`
		}](),
		reflect.TypeFor[struct {
			Items map[uint32][]byte `wire:"1,map,len=2,max_bytes=item,max_bits=item_bits,max_items=items"`
		}](),
	}
	for _, typ := range tests {
		if _, err := getSchema(typ); err != nil {
			t.Fatalf("rejected supported tag option combination in %s: %v", typ, err)
		}
	}
}

func TestSchemaRejectsMalformedPartyCompoundTypes(t *testing.T) {
	t.Parallel()

	tests := []reflect.Type{
		reflect.TypeFor[struct {
			Items []struct {
				Party uint32
				Bytes string
			} `wire:"1,partybytes"`
		}](),
		reflect.TypeFor[struct {
			Items []struct {
				Party  uint32
				First  []byte
				Second uint32
			} `wire:"1,partybytepairs"`
		}](),
	}
	for _, typ := range tests {
		if _, err := getSchema(typ); err == nil {
			t.Fatalf("accepted malformed compound type %s", typ)
		}
	}
}

func TestSchemaRejectsRetiredAllowEmptyOption(t *testing.T) {
	t.Parallel()

	type bad struct {
		Data []byte `wire:"1,bytes,allow_empty"`
	}
	if _, err := getSchema(reflect.TypeFor[bad]()); err == nil {
		t.Fatal("expected allow_empty to be rejected")
	}
}

func TestInferredKindRoundTripScenarios(t *testing.T) {
	t.Parallel()

	t.Run("basic inferred fields", func(t *testing.T) {
		t.Parallel()

		orig := inferredMessage{
			Name:  "test",
			Count: 42,
			Data:  []byte{1, 2, 3},
		}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded inferredMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Name != orig.Name || decoded.Count != orig.Count || !bytes.Equal(decoded.Data, orig.Data) {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	})

	t.Run("named primitive fields", func(t *testing.T) {
		t.Parallel()

		orig := namedInferredMessage{S: "hello", N: 7}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}

		var decoded namedInferredMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.S != orig.S || decoded.N != orig.N {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	})

	t.Run("inferred with options", func(t *testing.T) {
		t.Parallel()

		orig := inferredWithOptionsMessage{
			Hash: make([]byte, 32),
			Name: "test-name",
		}
		orig.Hash[0] = 0xff
		orig.Hash[31] = 0x01
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}

		var decoded inferredWithOptionsMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits())); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Hash, orig.Hash) || decoded.Name != orig.Name {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func TestInferredKindRejectsWrongType(t *testing.T) {
	t.Parallel()

	type badInferred struct {
		X int64 `wire:"1"`
	}
	if _, err := getSchema(reflect.TypeFor[badInferred]()); err == nil {
		t.Fatal("expected error for uninferrable type int64")
	}
}

func TestStringLimitRoundTripScenarios(t *testing.T) {
	t.Parallel()

	t.Run("explicit string limits", func(t *testing.T) {
		t.Parallel()

		orig := stringLimitMessage{
			Name: "short",
			Code: "ABCD",
		}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
		if err != nil {
			t.Fatal(err)
		}

		var decoded stringLimitMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits())); err != nil {
			t.Fatal(err)
		}
		if decoded.Name != orig.Name || decoded.Code != orig.Code {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	})

	t.Run("inferred string max bytes", func(t *testing.T) {
		t.Parallel()

		orig := stringLimitInferredMessage{Name: "test"}
		raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{"name": 10}))
		if err != nil {
			t.Fatal(err)
		}

		var decoded stringLimitInferredMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"name": 10})); err != nil {
			t.Fatal(err)
		}
		if decoded.Name != orig.Name {
			t.Fatalf("round-trip mismatch: got %q, want %q", decoded.Name, orig.Name)
		}
	})
}

func TestStringLimitRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "max bytes exceeded encode",
			run: func(t *testing.T) error {
				_, err := Marshal(stringLimitMessage{Name: "too-long-name", Code: "ABCD"}, WithFieldLimitsForMarshal(FieldLimits{"name": 5}))
				return err
			},
		},
		{
			name: "max bytes exceeded decode",
			run: func(t *testing.T) error {
				fields := []Field{
					{Tag: 1, Value: []byte("too-long-name")},
					{Tag: 2, Value: []byte("ABCD")},
				}
				raw, err := MarshalFields(1, "test.stringlimit", fields)
				if err != nil {
					return err
				}
				var decoded stringLimitMessage
				return Unmarshal(raw, &decoded, WithFrameLimits(FrameLimits{
					MaxTotalBytes: 1 << 20,
					MaxFields:     256,
					MaxFieldBytes: 1 << 20,
				}), WithFieldLimits(FieldLimits{"name": 5}))
			},
		},
		{
			name: "len mismatch encode",
			run: func(t *testing.T) error {
				_, err := Marshal(stringLimitMessage{Name: "ok", Code: "ABC"})
				return err
			},
		},
		{
			name: "len mismatch decode",
			run: func(t *testing.T) error {
				fields := []Field{
					{Tag: 1, Value: []byte("ok")},
					{Tag: 2, Value: []byte("AB")},
				}
				raw, err := MarshalFields(1, "test.stringlimit", fields)
				if err != nil {
					return err
				}
				var decoded stringLimitMessage
				return Unmarshal(raw, &decoded, WithFrameLimits(FrameLimits{
					MaxTotalBytes: 1 << 20,
					MaxFields:     256,
					MaxFieldBytes: 1 << 20,
				}))
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
