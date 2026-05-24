package paillier

import (
	"math/big"
	"testing"
)

func TestEncryptDecryptAndHomomorphicOps(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey
	c1, _, err := pk.Encrypt(nil, big.NewInt(12))
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := pk.Encrypt(nil, big.NewInt(30))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pk.AddCiphertexts(c1, c2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sk.Decrypt(sum)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("sum = %s, want 42", got)
	}
	scaled, err := pk.MulPlaintext(c1, big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}
	got, err = sk.Decrypt(scaled)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(36)) != 0 {
		t.Fatalf("scaled = %s, want 36", got)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := UnmarshalPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.Cmp(sk.N) != 0 || pub.G.Cmp(sk.G) != 0 {
		t.Fatal("public key mismatch after round trip")
	}
	privRaw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := UnmarshalPrivateKey(privRaw)
	if err != nil {
		t.Fatal(err)
	}
	if priv.N.Cmp(sk.N) != 0 || priv.Lambda.Cmp(sk.Lambda) != 0 {
		t.Fatal("private key mismatch after round trip")
	}
}

func TestRejectsNonCanonicalPublicKey(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := append([]byte(" "), raw...)
	if _, err := UnmarshalPublicKey(nonCanonical); err == nil {
		t.Fatal("expected non-canonical public key rejection")
	}
}

func TestValidateCiphertextGroup(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := sk.ValidateCiphertext(big.NewInt(0)); err == nil {
		t.Fatal("expected zero ciphertext rejection")
	}
	if err := sk.ValidateCiphertext(sk.NSquared); err == nil {
		t.Fatal("expected n^2 ciphertext rejection")
	}
	if err := sk.ValidateCiphertext(new(big.Int).Set(sk.N)); err == nil {
		t.Fatal("expected non-invertible ciphertext rejection")
	}
}
