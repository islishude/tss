package codec

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

func TestBytesList(t *testing.T) {
	items := [][]byte{{1}, {}, {2, 3}}
	raw := EncodeBytesList(items)
	got, err := DecodeBytesList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(items) {
		t.Fatalf("got %d items", len(got))
	}
	for i := range items {
		if !bytes.Equal(got[i], items[i]) {
			t.Fatalf("item %d got %x", i, got[i])
		}
	}
	if _, err := DecodeBytesList(append(raw, 0)); err == nil {
		t.Fatal("DecodeBytesList accepted trailing bytes")
	}
}
