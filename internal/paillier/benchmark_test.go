package paillier

import (
	"context"
	"math/big"
	"testing"
)

// Primitive: Paillier key generation at various bit sizes.
// Moved from keygen_test.go.

func BenchmarkGenerateKey2048(b *testing.B) {
	for b.Loop() {
		_, err := GenerateKeyForTest(context.Background(), nil, 2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKeyDefaultBits(b *testing.B) {
	for b.Loop() {
		_, err := GenerateKey(context.Background(), nil, 3072)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Primitive: Paillier encrypt/decrypt.

func BenchmarkPaillierEncrypt(b *testing.B) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		b.Fatal(err)
	}
	msg := big.NewInt(42)

	for b.Loop() {
		_, _, err := sk.Encrypt(nil, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPaillierDecrypt(b *testing.B) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		b.Fatal(err)
	}
	msg := big.NewInt(42)
	ct, _, err := sk.Encrypt(nil, msg)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		_, err := sk.Decrypt(ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}
