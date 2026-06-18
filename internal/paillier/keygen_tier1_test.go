//go:build tier1

package paillier

import (
	"context"
	"testing"

	"github.com/islishude/tss/internal/secret"
)

func TestGenerateKeyUsesSafePrimeFactorsAt1024Bits(t *testing.T) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if sk.N.BitLen() != 2048 {
		t.Fatalf("N has %d bits, want 2048", sk.N.BitLen())
	}
	p := scalarToBig(sk.P)
	q := scalarToBig(sk.Q)
	defer secret.ClearBigInt(p)
	defer secret.ClearBigInt(q)
	assertSafePrimeFactor(t, p, 1024)
	assertSafePrimeFactor(t, q, 1024)
}
