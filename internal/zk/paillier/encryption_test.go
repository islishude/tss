//go:build tier1

package paillier

import (
	"math/big"
	"testing"
)

func TestEncryptionProofTamper(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 1024)
	domain := []byte("encryption proof")
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveEncryption(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncryption(domain, &sk.PublicKey, ciphertext, proof) {
		t.Fatal("encryption proof did not verify")
	}
	if VerifyEncryption([]byte("other domain"), &sk.PublicKey, ciphertext, proof) {
		t.Fatal("encryption proof verified under wrong domain")
	}
	tampered := cloneEncryptionProof(proof)
	tampered.Response[0] ^= 1
	if VerifyEncryption(domain, &sk.PublicKey, ciphertext, tampered) {
		t.Fatal("tampered encryption proof verified")
	}
	if VerifyEncryption(domain, &sk.PublicKey, sk.NSquared, proof) {
		t.Fatal("invalid ciphertext outside Z*_{N^2} verified")
	}
}
