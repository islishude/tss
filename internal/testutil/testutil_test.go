package testutil

import (
	"testing"
)

func TestIsZeroBytes(t *testing.T) {
	// nil and empty are zero.
	if !IsZeroBytes(nil) {
		t.Error("nil slice should be zero")
	}
	if !IsZeroBytes([]byte{}) {
		t.Error("empty slice should be zero")
	}

	// All-zero of various lengths.
	for _, n := range []int{1, 4, 32, 128} {
		if !IsZeroBytes(make([]byte, n)) {
			t.Errorf("all-zero %d-byte slice should be zero", n)
		}
	}

	// Single non-zero byte.
	for pos := range 4 {
		b := make([]byte, 4)
		b[pos] = 1
		if IsZeroBytes(b) {
			t.Errorf("slice with non-zero at position %d should not be zero", pos)
		}
	}

	// Last byte non-zero.
	b := make([]byte, 64)
	b[63] = 0xFF
	if IsZeroBytes(b) {
		t.Error("slice with non-zero last byte should not be zero")
	}

	// All bytes non-zero.
	b = []byte{1, 2, 3, 4, 5}
	if IsZeroBytes(b) {
		t.Error("fully non-zero slice should not be zero")
	}
}
