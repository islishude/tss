package codec

import (
	"slices"
	"testing"
)

func TestUint32List(t *testing.T) {
	input := []testID{3, 7, 11}
	raw := EncodeUint32List(input)
	got, err := DecodeUint32List[testID](raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, input) {
		t.Fatalf("DecodeUint32List got %v", got)
	}
	if _, err := DecodeUint32List[testID]([]byte{0, 0, 0, 1, 0}); err == nil {
		t.Fatal("DecodeUint32List accepted invalid length")
	}
}

type testID uint32
