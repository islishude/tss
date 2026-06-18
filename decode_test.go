package tss

import (
	"errors"
	"strings"
	"testing"
)

type decodeTestValue struct {
	Value string
	Limit int
}

func (v *decodeTestValue) UnmarshalBinary(in []byte) error {
	if len(in) == 0 {
		return errors.New("empty input")
	}
	v.Value = string(in)
	return nil
}

func (v *decodeTestValue) UnmarshalBinaryWithLimits(in []byte, limit int) error {
	if len(in) > limit {
		return errors.New("input too large")
	}
	v.Value = string(in)
	v.Limit = limit
	return nil
}

type decodeTestNoUnmarshal struct{}

func TestDecodeBinary(t *testing.T) {
	t.Parallel()

	got, err := DecodeBinary[decodeTestValue]([]byte("ok"))
	if err != nil {
		t.Fatalf("DecodeBinary: %v", err)
	}
	if got.Value != "ok" {
		t.Fatalf("decoded value = %q, want ok", got.Value)
	}
}

func TestDecodeBinaryValue(t *testing.T) {
	t.Parallel()

	got, err := DecodeBinaryValue[decodeTestValue]([]byte("value"))
	if err != nil {
		t.Fatalf("DecodeBinaryValue: %v", err)
	}
	if got.Value != "value" {
		t.Fatalf("decoded value = %q, want value", got.Value)
	}
}

func TestDecodeBinaryRequiresUnmarshaler(t *testing.T) {
	t.Parallel()

	_, err := DecodeBinary[decodeTestNoUnmarshal]([]byte("x"))
	if err == nil {
		t.Fatal("DecodeBinary accepted type without BinaryUnmarshaler")
	}
	if !strings.Contains(err.Error(), "*tss.decodeTestNoUnmarshal") {
		t.Fatalf("error %q does not name target type", err)
	}
	if !strings.Contains(err.Error(), "encoding.BinaryUnmarshaler") {
		t.Fatalf("error %q does not name missing interface", err)
	}
}

func TestDecodeBinaryWithLimits(t *testing.T) {
	t.Parallel()

	got, err := DecodeBinaryWithLimits[decodeTestValue]([]byte("ok"), 2)
	if err != nil {
		t.Fatalf("DecodeBinaryWithLimits: %v", err)
	}
	if got.Value != "ok" || got.Limit != 2 {
		t.Fatalf("decoded value = %#v, want value ok with limit 2", got)
	}
}

func TestDecodeBinaryValueWithLimits(t *testing.T) {
	t.Parallel()

	got, err := DecodeBinaryValueWithLimits[decodeTestValue]([]byte("ok"), 2)
	if err != nil {
		t.Fatalf("DecodeBinaryValueWithLimits: %v", err)
	}
	if got.Value != "ok" || got.Limit != 2 {
		t.Fatalf("decoded value = %#v, want value ok with limit 2", got)
	}
}

func TestDecodeBinaryWithLimitsRequiresInterface(t *testing.T) {
	t.Parallel()

	_, err := DecodeBinaryWithLimits[decodeTestNoUnmarshal]([]byte("x"), 1)
	if err == nil {
		t.Fatal("DecodeBinaryWithLimits accepted type without limits-aware unmarshaler")
	}
	if !strings.Contains(err.Error(), "*tss.decodeTestNoUnmarshal") {
		t.Fatalf("error %q does not name target type", err)
	}
	if !strings.Contains(err.Error(), "BinaryUnmarshalerWithLimits") {
		t.Fatalf("error %q does not name missing interface", err)
	}
}

func TestDecodeBinaryWithLimitsPropagatesError(t *testing.T) {
	t.Parallel()

	if _, err := DecodeBinaryWithLimits[decodeTestValue]([]byte("too-big"), 3); err == nil {
		t.Fatal("DecodeBinaryWithLimits ignored limits error")
	}
}
