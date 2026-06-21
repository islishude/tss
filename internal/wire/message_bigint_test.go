package wire

import (
	"bytes"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestBigIntRoundTripScenarios(t *testing.T) {
	t.Parallel()

	t.Run("signed zero", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigIntSignedMessage{Val: big.NewInt(0)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntSignedMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Sign() != 0 {
			t.Fatalf("zero round-trip: got %v", decoded.Val)
		}
	})

	t.Run("signed positive", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigIntSignedMessage{Val: big.NewInt(258)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntSignedMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Cmp(big.NewInt(258)) != 0 {
			t.Fatalf("positive round-trip: got %v", decoded.Val)
		}
	})

	t.Run("signed negative", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigIntSignedMessage{Val: big.NewInt(-258)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntSignedMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Cmp(big.NewInt(-258)) != 0 {
			t.Fatalf("negative round-trip: got %v", decoded.Val)
		}
	})

	t.Run("signed required nil pointer rejects", func(t *testing.T) {
		t.Parallel()

		if _, err := Marshal(bigIntSignedMessage{Val: nil}); err == nil {
			t.Fatal("expected required nil bigint to be rejected")
		}
	})

	t.Run("signed pointer auto alloc", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigIntSignedMessage{Val: big.NewInt(42)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntSignedMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val == nil {
			t.Fatal("pointer field was not auto-allocated")
		}
		if decoded.Val.Cmp(big.NewInt(42)) != 0 {
			t.Fatalf("auto-alloc round-trip: got %v", decoded.Val)
		}
	})

	t.Run("signed value field", func(t *testing.T) {
		t.Parallel()

		orig := bigIntValueMessage{}
		orig.Val.SetInt64(-999)
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntValueMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Cmp(big.NewInt(-999)) != 0 {
			t.Fatalf("value field round-trip: got %v", &decoded.Val)
		}
	})
}

func TestBigIntCanonicalEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   *big.Int
		want []byte
	}{
		{name: "zero", in: big.NewInt(0), want: []byte{0x00}},
		{name: "positive", in: big.NewInt(258), want: []byte{0x00, 0x01, 0x02}},
		{name: "negative", in: big.NewInt(-258), want: []byte{0x01, 0x01, 0x02}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := encodeBigIntSigned(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("encoding: got %x, want %x", got, tc.want)
			}
		})
	}
}

func TestOptionalBigIntAllowsNil(t *testing.T) {
	t.Parallel()

	raw, err := Marshal(optionalBigIntMessage{})
	if err != nil {
		t.Fatal(err)
	}
	var decoded optionalBigIntMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val != nil {
		t.Fatalf("optional nil bigint decoded as %v", decoded.Val)
	}
}

func TestBigIntCanonicalRemarshal(t *testing.T) {
	t.Parallel()

	orig := bigIntSignedMessage{Val: big.NewInt(12345)}
	raw1, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("bigint marshal is not deterministic")
	}
}

func TestBigIntRejectsNonCanonicalSignedEncodings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value []byte
	}{
		{name: "invalid sign byte", value: []byte{0x02, 0x01}},
		{name: "negative zero", value: []byte{0x01}},
		{name: "leading zero magnitude", value: []byte{0x00, 0x00, 0x01}},
		{name: "empty", value: []byte{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := MarshalFields(1, "test.bigint.signed", []Field{{Tag: 1, Value: tc.value}})
			if err != nil {
				t.Fatal(err)
			}
			var decoded bigIntSignedMessage
			if err := Unmarshal(raw, &decoded); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestBigUintScenarios(t *testing.T) {
	t.Parallel()

	t.Run("zero round trip", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigUintMessage{Val: big.NewInt(0)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigUintMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Sign() != 0 {
			t.Fatalf("zero round-trip: got %v", decoded.Val)
		}
	})

	t.Run("positive round trip", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigUintMessage{Val: big.NewInt(258)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigUintMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Cmp(big.NewInt(258)) != 0 {
			t.Fatalf("positive round-trip: got %v", decoded.Val)
		}
	})

	t.Run("required nil pointer rejects", func(t *testing.T) {
		t.Parallel()

		if _, err := Marshal(bigUintMessage{Val: nil}); err == nil {
			t.Fatal("expected required nil biguint to be rejected")
		}
	})

	t.Run("negative marshal rejects", func(t *testing.T) {
		t.Parallel()

		if _, err := Marshal(bigUintMessage{Val: big.NewInt(-1)}); err == nil {
			t.Fatal("expected error for negative unsigned integer on marshal")
		}
	})

	t.Run("leading zero rejects", func(t *testing.T) {
		t.Parallel()

		raw, err := MarshalFields(1, "test.bigint.unsigned", []Field{{Tag: 1, Value: []byte{0x00, 0x01}}})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigUintMessage
		if err := Unmarshal(raw, &decoded); err == nil {
			t.Fatal("expected error for leading zero in unsigned integer")
		}
	})
}

func TestBigPosScenarios(t *testing.T) {
	t.Parallel()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigPosMessage{Val: big.NewInt(258)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigPosMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val.Cmp(big.NewInt(258)) != 0 {
			t.Fatalf("positive round-trip: got %v", decoded.Val)
		}
	})

	t.Run("pointer auto alloc", func(t *testing.T) {
		t.Parallel()

		raw, err := Marshal(bigPosMessage{Val: big.NewInt(7)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigPosMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Val == nil {
			t.Fatal("positive pointer was not auto-allocated")
		}
		if decoded.Val.Cmp(big.NewInt(7)) != 0 {
			t.Fatalf("auto-alloc round-trip: got %v", decoded.Val)
		}
	})
}

func TestBigPosRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "nil marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(bigPosMessage{Val: nil})
				return err
			},
		},
		{
			name: "zero marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(bigPosMessage{Val: big.NewInt(0)})
				return err
			},
		},
		{
			name: "negative marshal",
			run: func(t *testing.T) error {
				_, err := Marshal(bigPosMessage{Val: big.NewInt(-1)})
				return err
			},
		},
		{
			name: "empty decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.bigint.positive", []Field{{Tag: 1, Value: []byte{}}})
				if err != nil {
					return err
				}
				var decoded bigPosMessage
				return Unmarshal(raw, &decoded)
			},
		},
		{
			name: "leading zero decode",
			run: func(t *testing.T) error {
				raw, err := MarshalFields(1, "test.bigint.positive", []Field{{Tag: 1, Value: []byte{0x00, 0x01}}})
				if err != nil {
					return err
				}
				var decoded bigPosMessage
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

func TestBigPosMaxBitsEnforced(t *testing.T) {
	t.Parallel()

	// 0xABCD = 16 bits, encoded as 2 bytes for bigpos.
	raw, err := MarshalFields(1, "test.bigpos.maxbits", []Field{{Tag: 1, Value: []byte{0xAB, 0xCD}}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigPosMaxBitsMessage
	// max_bits=8: 16-bit integer should be rejected.
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 8})); err == nil {
		t.Fatal("expected max_bits error for 16-bit bigpos with limit 8")
	}
	// max_bits=1000: 16-bit integer should be accepted.
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 1000})); err != nil {
		t.Fatalf("unmarshal with adequate limit: %v", err)
	}
}

func TestBytesMaxBitsEnforced(t *testing.T) {
	t.Parallel()

	// 3-byte payload = 24 bits of byte-approximated size.
	raw, err := MarshalFields(1, "test.bytes.maxbits", []Field{{Tag: 1, Value: []byte{0x01, 0x02, 0x03}}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded bytesMaxBitsMessage
	// max_bits=8: 3 bytes × 8 = 24 > 8 should be rejected.
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 8})); err == nil {
		t.Fatal("expected max_bits error for 3-byte field with limit 8")
	}
	// max_bits=1000: 24 bits should be accepted.
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 1000})); err != nil {
		t.Fatalf("unmarshal with adequate limit: %v", err)
	}
}

func TestBigIntMaxBytesEnforced(t *testing.T) {
	t.Parallel()

	raw, err := MarshalFields(1, "test.bigint.maxbytes", []Field{{Tag: 1, Value: []byte{0x00, 0x01, 0x02}}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntMaxBytesMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 2})); err == nil {
		t.Fatal("expected max_bytes error for oversized bigint")
	}
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 10})); err != nil {
		t.Fatalf("unmarshal with adequate limit: %v", err)
	}
}

func TestBigIntErrorWrapping(t *testing.T) {
	t.Parallel()

	fields := []Field{
		{Tag: 1, Value: []byte{0x01}},
		{Tag: 2, Value: []byte{0x01, 0x02}},
	}
	raw, err := MarshalFields(1, "test.bigint.multifield", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntMultiFieldMessage
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error for negative zero")
	}
	if !strings.Contains(err.Error(), "Signed") || !strings.Contains(err.Error(), "tag 1") {
		t.Fatalf("error should mention field name and tag: %v", err)
	}
}

func TestBigIntFieldOrdering(t *testing.T) {
	t.Parallel()

	orig := bigIntMultiFieldMessage{
		Signed: big.NewInt(-5),
		Pos:    big.NewInt(3),
	}
	raw, err := Marshal(&orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntMultiFieldMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Signed.Cmp(big.NewInt(-5)) != 0 || decoded.Pos.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("field ordering broken: Signed=%v Pos=%v", decoded.Signed, decoded.Pos)
	}
}

func TestBigIntKindsRejectWrongGoFieldTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  reflect.Type
	}{
		{
			name: "bigint on string",
			typ: reflect.TypeFor[struct {
				Val string `wire:"1,bigint"`
			}](),
		},
		{
			name: "biguint on string",
			typ: reflect.TypeFor[struct {
				Val string `wire:"1,biguint"`
			}](),
		},
		{
			name: "bigpos on string",
			typ: reflect.TypeFor[struct {
				Val string `wire:"1,bigpos"`
			}](),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := getSchema(tc.typ); err == nil {
				t.Fatal("expected schema error")
			}
		})
	}
}

func FuzzBigIntField(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte{0x01, 0x01})
	f.Add([]byte{0x02, 0x01})
	f.Add([]byte{0x01})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, in []byte) {
		fields := []Field{
			{Tag: 1, Value: in},
		}
		raw, err := MarshalFields(1, "test.bigint.signed", fields)
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntSignedMessage
		_ = Unmarshal(raw, &decoded)

		raw2, err2 := MarshalFields(1, "test.bigint.unsigned", fields)
		if err2 != nil {
			t.Fatal(err2)
		}
		var decoded2 bigUintMessage
		_ = Unmarshal(raw2, &decoded2)

		raw3, err3 := MarshalFields(1, "test.bigint.positive", fields)
		if err3 != nil {
			t.Fatal(err3)
		}
		var decoded3 bigPosMessage
		_ = Unmarshal(raw3, &decoded3)
	})
}
