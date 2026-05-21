package paillier

import (
	"math/big"
	"testing"

	pai "github.com/islishude/tss/internal/paillier"
)

func TestEncryptedScalarProofTamper(t *testing.T) {
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.PublicKey.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveEncryptedScalar(nil, []byte("domain"), &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncryptedScalar([]byte("domain"), &sk.PublicKey, ciphertext, proof) {
		t.Fatal("proof did not verify")
	}
	proof.Response[0] ^= 1
	if VerifyEncryptedScalar([]byte("domain"), &sk.PublicKey, ciphertext, proof) {
		t.Fatal("tampered proof verified")
	}
}

func TestModulusProofTamper(t *testing.T) {
	sk, err := pai.GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveModulus([]byte("domain"), &sk.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyModulus([]byte("domain"), &sk.PublicKey, 1, proof) {
		t.Fatal("modulus proof did not verify")
	}
	if VerifyModulus([]byte("other"), &sk.PublicKey, 1, proof) {
		t.Fatal("modulus proof verified under wrong domain")
	}
}
