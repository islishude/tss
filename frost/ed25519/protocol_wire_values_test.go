package ed25519

import (
	"math/big"
	"slices"
	"testing"

	"github.com/islishude/tss/internal/curve/edwards25519"
)

func TestCanonicalScalarBoundaries(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{name: "zero", in: make([]byte, edwards25519.ScalarSize)},
		{name: "q minus one", in: testEd25519ScalarEncodingLE(t, edwards25519.Order(), -1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newCanonicalScalarFromBytes(tc.in); err != nil {
				t.Fatalf("canonical scalar rejected: %v", err)
			}
		})
	}

	highBitsSet := make([]byte, edwards25519.ScalarSize)
	highBitsSet[len(highBitsSet)-1] = 0xe0
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{name: "q", in: testEd25519ScalarEncodingLE(t, edwards25519.Order(), 0)},
		{name: "q plus one", in: testEd25519ScalarEncodingLE(t, edwards25519.Order(), 1)},
		{name: "high three bits", in: highBitsSet},
		{name: "short", in: make([]byte, edwards25519.ScalarSize-1)},
		{name: "long", in: make([]byte, edwards25519.ScalarSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newCanonicalScalarFromBytes(tc.in); err == nil {
				t.Fatal("non-canonical scalar accepted")
			}
			var decoded canonicalScalar
			if err := decoded.UnmarshalWireValue(tc.in); err == nil {
				t.Fatal("wire scalar decoder accepted non-canonical input")
			}
		})
	}
}

func testEd25519ScalarEncodingLE(t testing.TB, order *big.Int, delta int64) []byte {
	t.Helper()
	value := new(big.Int).Set(order)
	value.Add(value, big.NewInt(delta))
	out := value.FillBytes(make([]byte, edwards25519.ScalarSize))
	slices.Reverse(out)
	return out
}
