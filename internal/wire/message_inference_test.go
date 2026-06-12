package wire

import (
	"bytes"
	"reflect"
	"testing"
)

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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.run(t); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
