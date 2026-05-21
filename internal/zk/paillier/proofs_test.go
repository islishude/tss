package paillier

import (
	"math/big"
	"testing"

	pai "github.com/islishude/tss/internal/paillier"
)

func TestEncryptedScalarProofTamper(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.PublicKey.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	encProof, rangeProof, err := ProveEncScalarAndRange(nil, []byte("domain"), &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncScalarAndRange([]byte("domain"), &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("proof did not verify")
	}
	encProof.Response[0] ^= 1
	if VerifyEncScalarAndRange([]byte("domain"), &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("tampered enc proof verified")
	}
	encProof.Response[0] ^= 1
	rangeProof.Digest[0] ^= 1
	if VerifyEncScalarAndRange([]byte("domain"), &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("tampered range proof verified")
	}
}

func TestModulusProofTamper(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(512)
	defer restore()
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
	proof.Digest[0] ^= 1
	if VerifyModulus([]byte("domain"), &sk.PublicKey, 1, proof) {
		t.Fatal("tampered modulus proof verified")
	}
}
