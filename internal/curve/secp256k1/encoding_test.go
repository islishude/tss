package secp256k1

import (
	"bytes"
	"testing"
)

func TestScalarWireValueRoundTrip(t *testing.T) {
	want := ScalarFromUint64(42)
	raw, err := want.MarshalWireValue()
	if err != nil {
		t.Fatalf("MarshalWireValue: %v", err)
	}
	if len(raw) != ScalarSize {
		t.Fatalf("encoded scalar length = %d, want %d", len(raw), ScalarSize)
	}

	var decoded Scalar
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatalf("UnmarshalWireValue: %v", err)
	}
	if !decoded.Equal(want) {
		t.Fatal("decoded scalar mismatch")
	}
}

func TestScalarWireValueAllowsZero(t *testing.T) {
	raw, err := ScalarZero().MarshalWireValue()
	if err != nil {
		t.Fatalf("MarshalWireValue: %v", err)
	}
	if !bytes.Equal(raw, make([]byte, ScalarSize)) {
		t.Fatal("zero scalar did not encode as fixed-width zero")
	}

	var decoded Scalar
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatalf("UnmarshalWireValue: %v", err)
	}
	if !decoded.IsZero() {
		t.Fatal("decoded scalar should be zero")
	}
}

func TestScalarWireValueRejectsMalformedLength(t *testing.T) {
	var decoded Scalar
	if err := decoded.UnmarshalWireValue([]byte{1, 2, 3}); err == nil {
		t.Fatal("accepted malformed scalar length")
	}
}

func TestScalarWireValueRejectsOutOfRange(t *testing.T) {
	var decoded Scalar
	if err := decoded.UnmarshalWireValue(scalarModulus[:]); err == nil {
		t.Fatal("accepted scalar equal to group order")
	}
}

func TestPointWireValueRoundTrip(t *testing.T) {
	want := ScalarBaseMult(ScalarFromUint64(42))
	raw, err := want.MarshalWireValue()
	if err != nil {
		t.Fatalf("MarshalWireValue: %v", err)
	}
	if len(raw) != 33 {
		t.Fatalf("encoded point length = %d, want 33", len(raw))
	}

	var decoded Point
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatalf("UnmarshalWireValue: %v", err)
	}
	if !Equal(&decoded, want) {
		t.Fatal("decoded point mismatch")
	}
}

func TestPointWireValueRejectsInfinity(t *testing.T) {
	if _, err := NewInfinity().MarshalWireValue(); err == nil {
		t.Fatal("encoded point at infinity")
	}
}
