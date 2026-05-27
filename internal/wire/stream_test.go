package wire

import (
	"bytes"
	"testing"
)

func TestNonNilBytes(t *testing.T) {
	if got := NonNilBytes(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil converted to %#v", got)
	}
	input := []byte{1, 2}
	if got := NonNilBytes(input); !bytes.Equal(got, input) {
		t.Fatalf("non-nil bytes changed to %x", got)
	}
}

func TestReadAppendBytes(t *testing.T) {
	raw := AppendBytes([]byte{9}, []byte{1, 2, 3})
	if !bytes.Equal(raw, []byte{9, 0, 0, 0, 3, 1, 2, 3}) {
		t.Fatalf("AppendBytes encoded %x", raw)
	}
	got, offset, err := ReadBytes(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) || offset != len(raw) {
		t.Fatalf("ReadBytes got %x at %d", got, offset)
	}
	if _, _, err := ReadBytes([]byte{0, 0, 0, 3, 1}, 0); err == nil {
		t.Fatal("ReadBytes accepted truncated byte field")
	}
}

func TestReadUint16(t *testing.T) {
	got, offset, err := ReadUint16([]byte{2, 1, 2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x0102 || offset != 3 {
		t.Fatalf("ReadUint16 got %x at %d", got, offset)
	}
	if _, _, err := ReadUint16([]byte{2, 1, 2}, 2); err == nil {
		t.Fatal("ReadUint16 accepted truncated input")
	}
}

func TestReadUint32(t *testing.T) {
	got, offset, err := ReadUint32([]byte{9, 1, 2, 3, 4}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x01020304 || offset != 5 {
		t.Fatalf("ReadUint32 got %x at %d", got, offset)
	}
	if _, _, err := ReadUint32([]byte{1, 2, 3}, 0); err == nil {
		t.Fatal("ReadUint32 accepted truncated input")
	}
}
