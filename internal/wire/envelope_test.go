package wire

import (
	"bytes"
	"testing"
)

func TestMarshalRoundTrip(t *testing.T) {
	raw, err := Marshal(1, "test.type", []Field{
		{Tag: 1, Value: []byte("a")},
		{Tag: 2, Value: []byte("bb")},
	})
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := Unmarshal(raw, "test.type")
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("version=%d", version)
	}
	if len(fields) != 2 || fields[0].Tag != 1 || !bytes.Equal(fields[1].Value, []byte("bb")) {
		t.Fatalf("unexpected fields: %#v", fields)
	}
	raw2, err := Marshal(1, "test.type", fields)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatal("wire encoding is not deterministic")
	}
}

func TestMarshalRejectsDuplicateOrUnsortedTags(t *testing.T) {
	if _, err := Marshal(1, "test.type", []Field{{Tag: 2, Value: []byte{1}}, {Tag: 1, Value: []byte{2}}}); err == nil {
		t.Fatal("unsorted tags accepted")
	}
	if _, err := Marshal(1, "test.type", []Field{{Tag: 1, Value: []byte{1}}, {Tag: 1, Value: []byte{2}}}); err == nil {
		t.Fatal("duplicate tags accepted")
	}
}

func TestUnmarshalRejectsTrailingBytes(t *testing.T) {
	raw, err := Marshal(1, "test.type", []Field{{Tag: 1, Value: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0)
	if _, _, err := Unmarshal(raw, "test.type"); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

func TestUnmarshalRejectsWrongTypeID(t *testing.T) {
	raw, err := Marshal(1, "test.type", []Field{{Tag: 1, Value: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Unmarshal(raw, "other.type"); err == nil {
		t.Fatal("wrong type id accepted")
	}
}

func FuzzWireUnmarshal(f *testing.F) {
	raw, err := Marshal(1, "test.type", []Field{{Tag: 1, Value: []byte("seed")}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("not-wire"))
	f.Fuzz(func(t *testing.T, data []byte) {
		version, fields, err := Unmarshal(data, "test.type")
		if err != nil {
			return
		}
		again, err := Marshal(version, "test.type", fields)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, again) {
			t.Fatal("wire did not remarshal deterministically")
		}
	})
}
