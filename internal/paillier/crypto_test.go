package paillier

import (
	"context"
	"math/big"
	"testing"
)

func TestEncryptDecryptAndHomomorphicOps(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	t.Cleanup(restore)
	sk, err := GenerateKey(context.Background(), nil, 512)
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

func TestValidateCiphertextGroup(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	t.Cleanup(restore)
	sk, err := GenerateKey(context.Background(), nil, 512)
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

func TestDecryptRejectsNonUnitCiphertext(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	t.Cleanup(restore)
	sk, err := GenerateKey(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	// N is in range (0 < N < N^2) but gcd(N, N^2) = N, not 1.
	bad := new(big.Int).Set(sk.N)
	if _, err := sk.Decrypt(bad); err == nil {
		t.Fatal("expected Decrypt to reject non-unit ciphertext N")
	}
	// Zero.
	if _, err := sk.Decrypt(big.NewInt(0)); err == nil {
		t.Fatal("expected Decrypt to reject zero ciphertext")
	}
	// N^2 (out of range).
	if _, err := sk.Decrypt(sk.NSquared); err == nil {
		t.Fatal("expected Decrypt to reject N^2 ciphertext")
	}
	// Valid ciphertext still works.
	c, _, err := sk.Encrypt(nil, big.NewInt(42))
	if err != nil {
		t.Fatal(err)
	}
	m, err := sk.Decrypt(c)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("Decrypt: got %s, want 42", m)
	}
}

func TestCheckedHomomorphicRejectNonUnitCiphertext(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	t.Cleanup(restore)
	sk, err := GenerateKey(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := &sk.PublicKey

	// N is in range but not coprime to N^2.
	bad := new(big.Int).Set(sk.N)
	good, _, err := pk.Encrypt(nil, big.NewInt(7))
	if err != nil {
		t.Fatal(err)
	}

	// AddCiphertexts rejects non-unit left.
	if _, err := pk.AddCiphertexts(bad, good); err == nil {
		t.Fatal("AddCiphertexts accepted non-unit left ciphertext")
	}
	// AddCiphertexts rejects non-unit right.
	if _, err := pk.AddCiphertexts(good, bad); err == nil {
		t.Fatal("AddCiphertexts accepted non-unit right ciphertext")
	}
	// AddPlaintext rejects non-unit ciphertext.
	if _, err := pk.AddPlaintext(bad, big.NewInt(1)); err == nil {
		t.Fatal("AddPlaintext accepted non-unit ciphertext")
	}
	// MulPlaintext rejects non-unit ciphertext.
	if _, err := pk.MulPlaintext(bad, big.NewInt(2)); err == nil {
		t.Fatal("MulPlaintext accepted non-unit ciphertext")
	}

	// Valid operations still work.
	sum, err := pk.AddCiphertexts(good, good)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sk.Decrypt(sum)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cmp(big.NewInt(14)) != 0 {
		t.Fatalf("AddCiphertexts: 7+7 got %s", m)
	}
}

func TestUncheckedHelpersRejectOutOfRange(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	t.Cleanup(restore)
	sk, err := GenerateKey(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := &sk.PublicKey

	// AddCiphertextsUnchecked rejects nil.
	if _, err := pk.AddCiphertextsUnchecked(nil, big.NewInt(1)); err == nil {
		t.Fatal("AddCiphertextsUnchecked accepted nil a")
	}
	if _, err := pk.AddCiphertextsUnchecked(big.NewInt(1), nil); err == nil {
		t.Fatal("AddCiphertextsUnchecked accepted nil b")
	}
	// AddCiphertextsUnchecked rejects zero.
	if _, err := pk.AddCiphertextsUnchecked(big.NewInt(0), big.NewInt(1)); err == nil {
		t.Fatal("AddCiphertextsUnchecked accepted zero a")
	}
	// AddCiphertextsUnchecked rejects out-of-range.
	if _, err := pk.AddCiphertextsUnchecked(pk.NSquared, big.NewInt(1)); err == nil {
		t.Fatal("AddCiphertextsUnchecked accepted N^2")
	}

	// AddPlaintextUnchecked rejects nil.
	if _, err := pk.AddPlaintextUnchecked(nil, big.NewInt(1)); err == nil {
		t.Fatal("AddPlaintextUnchecked accepted nil ciphertext")
	}
	// AddPlaintextUnchecked rejects zero.
	if _, err := pk.AddPlaintextUnchecked(big.NewInt(0), big.NewInt(1)); err == nil {
		t.Fatal("AddPlaintextUnchecked accepted zero ciphertext")
	}

	// MulPlaintextUnchecked rejects nil.
	if _, err := pk.MulPlaintextUnchecked(nil, big.NewInt(1)); err == nil {
		t.Fatal("MulPlaintextUnchecked accepted nil ciphertext")
	}
	// MulPlaintextUnchecked rejects zero.
	if _, err := pk.MulPlaintextUnchecked(big.NewInt(0), big.NewInt(1)); err == nil {
		t.Fatal("MulPlaintextUnchecked accepted zero ciphertext")
	}
}

func TestUncheckedHelpersAcceptValidCiphertexts(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	t.Cleanup(restore)
	sk, err := GenerateKey(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := &sk.PublicKey

	c1, _, err := pk.Encrypt(nil, big.NewInt(10))
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := pk.Encrypt(nil, big.NewInt(20))
	if err != nil {
		t.Fatal(err)
	}

	// AddCiphertextsUnchecked with valid inputs.
	sum, err := pk.AddCiphertextsUnchecked(c1, c2)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sk.Decrypt(sum)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cmp(big.NewInt(30)) != 0 {
		t.Fatalf("AddCiphertextsUnchecked: 10+20 got %s", m)
	}

	// AddPlaintextUnchecked with valid input.
	sum2, err := pk.AddPlaintextUnchecked(c1, big.NewInt(5))
	if err != nil {
		t.Fatal(err)
	}
	m, err = sk.Decrypt(sum2)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cmp(big.NewInt(15)) != 0 {
		t.Fatalf("AddPlaintextUnchecked: 10+5 got %s", m)
	}

	// MulPlaintextUnchecked with valid input.
	prod, err := pk.MulPlaintextUnchecked(c1, big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}
	m, err = sk.Decrypt(prod)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cmp(big.NewInt(30)) != 0 {
		t.Fatalf("MulPlaintextUnchecked: 10*3 got %s", m)
	}
}
