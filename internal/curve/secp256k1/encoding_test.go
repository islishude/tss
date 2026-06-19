package secp256k1

import (
	"bytes"
	"testing"
)

func TestWireScalarRoundTrip(t *testing.T) {
	want := ScalarFromUint64(42)
	raw, err := (WireScalar{S: want}).MarshalWireValue()
	if err != nil {
		t.Fatalf("MarshalWireValue: %v", err)
	}
	if len(raw) != ScalarSize {
		t.Fatalf("encoded scalar length = %d, want %d", len(raw), ScalarSize)
	}

	var decoded WireScalar
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatalf("UnmarshalWireValue: %v", err)
	}
	if !decoded.S.Equal(want) {
		t.Fatal("decoded scalar mismatch")
	}
}

func TestWireScalarAllowsZero(t *testing.T) {
	raw, err := (WireScalar{S: ScalarZero()}).MarshalWireValue()
	if err != nil {
		t.Fatalf("MarshalWireValue: %v", err)
	}
	if !bytes.Equal(raw, make([]byte, ScalarSize)) {
		t.Fatal("zero scalar did not encode as fixed-width zero")
	}

	var decoded WireScalar
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatalf("UnmarshalWireValue: %v", err)
	}
	if !decoded.S.IsZero() {
		t.Fatal("decoded scalar should be zero")
	}
}

func TestWireScalarRejectsMalformedLength(t *testing.T) {
	var decoded WireScalar
	if err := decoded.UnmarshalWireValue([]byte{1, 2, 3}); err == nil {
		t.Fatal("accepted malformed scalar length")
	}
}

func TestWireScalarRejectsOutOfRange(t *testing.T) {
	var decoded WireScalar
	if err := decoded.UnmarshalWireValue(scalarModulus[:]); err == nil {
		t.Fatal("accepted scalar equal to group order")
	}
}
