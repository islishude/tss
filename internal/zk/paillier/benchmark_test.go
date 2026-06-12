//go:build tier1

package paillier

import (
	"math/big"
	"testing"
)

// Verification: proof creation and checking.

func BenchmarkZKEncryptionProofProve(b *testing.B) {
	sk := testPaillierKey(b, 1024)
	domain := []byte("benchmark zk enc")
	scalar := big.NewInt(42)

	for b.Loop() {
		ciphertext, randomness, err := sk.Encrypt(nil, scalar)
		if err != nil {
			b.Fatal(err)
		}
		_, err = ProveEncryption(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
		if err != nil {
			b.Fatal(err)
		}
	}
}

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
