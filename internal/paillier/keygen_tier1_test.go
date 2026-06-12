//go:build tier1

package paillier

import (
	"context"
	"testing"
)

func TestGenerateKeyUsesSafePrimeFactorsAt1024Bits(t *testing.T) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if sk.N.BitLen() != 2048 {
		t.Fatalf("N has %d bits, want 2048", sk.N.BitLen())
	}
	assertSafePrimeFactor(t, sk.P, 1024)
	assertSafePrimeFactor(t, sk.Q, 1024)
}
