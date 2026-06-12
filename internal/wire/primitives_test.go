package wire

import (
	"bytes"
	"testing"
)

func TestUintPrimitives(t *testing.T) {
	t.Parallel()
	if got := Uint16(0x1234); !bytes.Equal(got, []byte{0x12, 0x34}) {
		t.Fatalf("Uint16 encoded %x", got)
	}
	if got := Uint32(0x12345678); !bytes.Equal(got, []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Fatalf("Uint32 encoded %x", got)
	}
	if got, err := DecodeUint16([]byte{0x12, 0x34}); err != nil || got != 0x1234 {
		t.Fatalf("DecodeUint16 got %x, %v", got, err)
	}
	if got, err := DecodeUint32([]byte{0x12, 0x34, 0x56, 0x78}); err != nil || got != 0x12345678 {
		t.Fatalf("DecodeUint32 got %x, %v", got, err)
	}
	if _, err := DecodeUint16([]byte{0x12}); err == nil {
		t.Fatal("DecodeUint16 accepted short input")
	}
	if _, err := DecodeUint32([]byte{0x12, 0x34, 0x56}); err == nil {
		t.Fatal("DecodeUint32 accepted short input")
	}
}

func TestBoolPrimitive(t *testing.T) {
	t.Parallel()
	if got := Bool(true); !bytes.Equal(got, []byte{1}) {
		t.Fatalf("true encoded %x", got)
	}
	if got := Bool(false); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("false encoded %x", got)
	}
	if got, err := DecodeBool([]byte{1}); err != nil || !got {
		t.Fatalf("DecodeBool true got %v, %v", got, err)
	}
	if got, err := DecodeBool([]byte{0}); err != nil || got {
		t.Fatalf("DecodeBool false got %v, %v", got, err)
	}
	if _, err := DecodeBool([]byte{2}); err == nil {
		t.Fatal("DecodeBool accepted non-canonical value")
	}
	if _, err := DecodeBool([]byte{}); err == nil {
		t.Fatal("DecodeBool accepted empty input")
	}
}
