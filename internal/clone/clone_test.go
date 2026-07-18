package clone

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"
)

func TestByteSlicesPreservesNilAndEmpty(t *testing.T) {
	t.Parallel()

	if got := ByteSlices(nil); got != nil {
		t.Fatalf("ByteSlices(nil) = %v, want nil", got)
	}

	got := ByteSlices([][]byte{})
	if got == nil {
		t.Fatal("ByteSlices(empty) returned nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("len(ByteSlices(empty)) = %d, want 0", len(got))
	}
}

func TestByteSlicesDeepCopiesOuterAndInnerSlices(t *testing.T) {
	t.Parallel()

	in := [][]byte{nil, {0x01, 0x02}, {0x03}}
	got := ByteSlices(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("ByteSlices() = %v, want %v", got, in)
	}
	if got[0] != nil {
		t.Fatalf("ByteSlices() cloned nil inner slice as %v, want nil", got[0])
	}
	if &got[1] == &in[1] {
		t.Fatal("ByteSlices() reused outer slice storage")
	}
	if &got[1][0] == &in[1][0] {
		t.Fatal("ByteSlices() reused inner slice storage")
	}

	got[1][0] = 0xff
	if bytes.Equal(got[1], in[1]) {
		t.Fatal("mutating cloned inner slice changed the original")
	}
}

type testValue struct {
	id   string
	data []byte
}

func (v testValue) Clone() testValue {
	return testValue{
		id:   v.id,
		data: bytes.Clone(v.data),
	}
}

func TestSlicePreservesNilAndEmpty(t *testing.T) {
	t.Parallel()

	if got := Slice[testValue](nil); got != nil {
		t.Fatalf("Slice(nil) = %#v, want nil", got)
	}

	got := Slice([]testValue{})
	if got == nil {
		t.Fatal("Slice(empty) returned nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("len(Slice(empty)) = %d, want 0", len(got))
	}
}

func TestSliceDeepCopiesElements(t *testing.T) {
	t.Parallel()

	in := []testValue{
		{id: "alice", data: []byte{1, 2, 3}},
		{id: "bob", data: []byte{4, 5, 6}},
	}
	got := Slice(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("Slice() = %#v, want %#v", got, in)
	}
	if &got[0] == &in[0] {
		t.Fatal("Slice() reused outer slice storage")
	}
	if &got[0].data[0] == &in[0].data[0] {
		t.Fatal("Slice() reused element backing storage")
	}

	got[0].data[0] = 99
	if in[0].data[0] != 1 {
		t.Fatalf("mutating cloned element changed original data: got %d, want 1", in[0].data[0])
	}
}

func TestMapPreservesNilAndEmpty(t *testing.T) {
	t.Parallel()

	if got := Map[string, testValue](nil); got != nil {
		t.Fatalf("Map(nil) = %#v, want nil", got)
	}

	got := Map(map[string]testValue{})
	if got == nil {
		t.Fatal("Map(empty) returned nil, want empty non-nil map")
	}
	if len(got) != 0 {
		t.Fatalf("len(Map(empty)) = %d, want 0", len(got))
	}
}

func TestMapDeepCopiesValues(t *testing.T) {
	t.Parallel()

	in := map[string]testValue{
		"alice": {id: "alice", data: []byte{1, 2, 3}},
		"bob":   {id: "bob", data: []byte{4, 5, 6}},
	}
	got := Map(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("Map() = %#v, want %#v", got, in)
	}

	value := got["alice"]
	value.data[0] = 99
	if in["alice"].data[0] != 1 {
		t.Fatalf("mutating cloned value changed original data: got %d, want 1", in["alice"].data[0])
	}
}

func TestBigIntPreservesNilAndValue(t *testing.T) {
	t.Parallel()

	if got := BigInt(nil); got != nil {
		t.Fatalf("BigInt(nil) = %v, want nil", got)
	}

	values := []*big.Int{
		big.NewInt(0),
		big.NewInt(123456789),
		big.NewInt(-123456789),
	}
	large, ok := new(big.Int).SetString("1234567890123456789012345678901234567890", 10)
	if !ok {
		t.Fatal("failed to construct test big.Int")
	}
	values = append(values, large)

	for _, value := range values {
		t.Run(value.String(), func(t *testing.T) {
			t.Parallel()

			got := BigInt(value)
			if got == value {
				t.Fatal("BigInt() returned the input pointer")
			}
			if got.Cmp(value) != 0 {
				t.Fatalf("BigInt(%v) = %v, want equal value", value, got)
			}

			original := new(big.Int).Set(value)
			got.Add(got, big.NewInt(1))
			if value.Cmp(original) != 0 {
				t.Fatalf("mutating clone changed original: got %v, want %v", value, original)
			}
		})
	}
}
