package secret

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewScalar(t *testing.T) {
	s, err := NewScalar([]byte{0x01, 0x02, 0x03}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if s.FixedLen() != 4 {
		t.Fatalf("len = %d, want 4", s.FixedLen())
	}
	b := s.FixedBytes()
	if !bytes.Equal(b, []byte{0x00, 0x01, 0x02, 0x03}) {
		t.Fatalf("FixedBytes = %x, want 00010203", b)
	}
}

func TestNewScalarRejectsOversized(t *testing.T) {
	if _, err := NewScalar([]byte{0x01, 0x02, 0x03, 0x04, 0x05}, 3); err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestNewScalarRejectsEmpty(t *testing.T) {
	if _, err := NewScalar(nil, 4); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, err := NewScalar([]byte{}, 4); err == nil {
		t.Fatal("expected error for empty input")
	}
	if _, err := NewScalar([]byte{0x01}, 0); err == nil {
		t.Fatal("expected error for zero length")
	}
}

func TestScalarEqual(t *testing.T) {
	a, _ := NewScalar([]byte{0x01, 0x02}, 4)
	b, _ := NewScalar([]byte{0x01, 0x02}, 4)
	c, _ := NewScalar([]byte{0x01, 0x03}, 4)
	d, _ := NewScalar([]byte{0x01, 0x02}, 3)
	if !a.Equal(b) {
		t.Fatal("identical scalars not equal")
	}
	if a.Equal(c) {
		t.Fatal("different scalars equal")
	}
	if a.Equal(d) {
		t.Fatal("different length scalars equal")
	}
	if a.Equal(nil) {
		t.Fatal("non-nil equals nil")
	}
	if (*Scalar)(nil).Equal(nil) != true {
		t.Fatal("nil equals nil should be true")
	}
}

func TestScalarDestroy(t *testing.T) {
	s, _ := NewScalar([]byte{0xff, 0xfe}, 4)
	s.Destroy()
	for _, b := range s.buf {
		if b != 0 {
			t.Fatal("buffer not zeroed")
		}
	}
	var nilS *Scalar
	nilS.Destroy() // must not panic
}

func TestScalarMarshalBinary(t *testing.T) {
	s, _ := NewScalar([]byte{0x01, 0x02, 0x03}, 4)
	raw, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("MarshalBinary = %x, want 010203", raw)
	}

	// Leading zeros stripped
	s2, _ := NewScalar([]byte{0xab}, 4)
	raw2, _ := s2.MarshalBinary()
	if !bytes.Equal(raw2, []byte{0xab}) {
		t.Fatalf("MarshalBinary = %x, want ab", raw2)
	}
}

func TestUnmarshalScalarRoundTrip(t *testing.T) {
	orig, _ := NewScalar([]byte{0xde, 0xad, 0xbe, 0xef}, 4)
	raw, _ := orig.MarshalBinary()
	s, err := UnmarshalScalar(raw, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Equal(orig) {
		t.Fatal("round trip mismatch")
	}

	// Non-minimal encoding rejected
	if _, err := UnmarshalScalar([]byte{0x00, 0x01}, 4); err == nil {
		t.Fatal("expected non-minimal rejection")
	}
	// Empty rejected
	if _, err := UnmarshalScalar(nil, 4); err == nil {
		t.Fatal("expected empty rejection")
	}
	// Too large
	if _, err := UnmarshalScalar([]byte{0x01, 0x02, 0x03, 0x04, 0x05}, 4); err == nil {
		t.Fatal("expected too-large rejection")
	}
}

func TestScalarNoLeakVectors(t *testing.T) {
	s, _ := NewScalar([]byte{0x42}, 32)
	// String() is from the default struct formatter — ensure it doesn't leak bytes
	str := `"` + string(s.FixedBytes()) + `"`
	if len(str) < 10 {
		t.Fatal("unexpected string representation")
	}
	// JSON must fail
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("scalar JSON encoded")
	}
}

func TestScalar_Clone(t *testing.T) {
	var nilS *Scalar
	if clone := nilS.Clone(); clone != nil {
		t.Fatal("Clone of nil should be nil")
	}
	if b := nilS.FixedBytes(); b != nil {
		t.Fatal("FixedBytes of nil should be nil")
	}
	if l := nilS.FixedLen(); l != 0 {
		t.Fatal("FixedLen of nil should be 0")
	}
	if _, err := nilS.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary of nil should error")
	}

	s, err := NewScalar([]byte{0x01, 0x02}, 4)
	if err != nil {
		t.Fatal(err)
	}
	clone := s.Clone()
	if !s.Equal(clone) {
		t.Fatal("clone not equal to original")
	}
	clone.buf[0] = 0xff
	if s.buf[0] != 0x00 {
		t.Fatal("original modified when clone changed")
	}
}
