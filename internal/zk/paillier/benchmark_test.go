//go:build tier1

package paillier

import "testing"

// Verification: proof creation and checking.

func BenchmarkZKModulusProofProve(b *testing.B) {
	sk := testPaillierKey(b, 512)
	domain := []byte("benchmark zk mod")

	for b.Loop() {
		_, err := ProveModulus(nil, domain, sk, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}
