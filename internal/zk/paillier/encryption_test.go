package paillier

import (
	"bytes"
	"math/big"
	"testing"
)

func TestEncryptionProofTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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

func assertEncryptionProofRoundTrip(t *testing.T, proof *EncryptionProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEncryptionProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("encryption proof encoding is not deterministic")
	}
	if _, err := UnmarshalEncryptionProof(append(raw, 0)); err == nil {
		t.Fatal("encryption proof accepted trailing bytes")
	}
}

func cloneEncryptionProof(in *EncryptionProof) *EncryptionProof {
	out := *in
	out.ScalarCommitment = append([]byte(nil), in.ScalarCommitment...)
	out.CipherCommitment = append([]byte(nil), in.CipherCommitment...)
	out.PointCommitment = append([]byte(nil), in.PointCommitment...)
	out.Bound = append([]byte(nil), in.Bound...)
	out.Response = append([]byte(nil), in.Response...)
	out.Randomness = append([]byte(nil), in.Randomness...)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	return &out
}
