package paillier

import (
	"context"
	"math/big"
	"testing"
)

func TestEncryptDecryptAndHomomorphicOps(t *testing.T) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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

func TestEncryptWithRandomnessDeterministic(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey
	m := big.NewInt(42)
	r := big.NewInt(13)

	c1, err := pk.EncryptWithRandomness(m, r)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := pk.EncryptWithRandomness(m, r)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Cmp(c2) != 0 {
		t.Fatal("EncryptWithRandomness is not deterministic: same (m,r) produced different ciphetexts")
	}

	// Verify decryption round-trips.
	got, err := sk.Decrypt(c1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(m) != 0 {
		t.Fatalf("EncryptWithRandomness/Decrypt round-trip: got %s, want %s", got, m)
	}

	// Different randomness → different ciphertext.
	c3, err := pk.EncryptWithRandomness(m, big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}
	if c1.Cmp(c3) == 0 {
		t.Fatal("different randomness produced identical ciphertexts")
	}
	got, err = sk.Decrypt(c3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(m) != 0 {
		t.Fatalf("c3 decrypt: got %s, want %s", got, m)
	}
}

func TestEncryptWithRandomnessRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey

	// Nil message.
	if _, err := pk.EncryptWithRandomness(nil, big.NewInt(1)); err == nil {
		t.Fatal("nil message accepted")
	}
	// Nil randomness.
	if _, err := pk.EncryptWithRandomness(big.NewInt(1), nil); err == nil {
		t.Fatal("nil randomness accepted")
	}
	// r not coprime to N.
	badR := new(big.Int).Mul(sk.P, big.NewInt(2)) // multiple of P, not coprime to N
	if _, err := pk.EncryptWithRandomness(big.NewInt(1), badR); err == nil {
		t.Fatal("non-coprime randomness accepted")
	}
	// r = N (divisible by N, not coprime).
	if _, err := pk.EncryptWithRandomness(big.NewInt(1), new(big.Int).Set(sk.N)); err == nil {
		t.Fatal("r=N accepted")
	}
}

func TestLFunction(t *testing.T) {
	t.Parallel()
	// For n=15: L(16) = (16-1)/15 = 1
	n := big.NewInt(15)
	if got := L(big.NewInt(16), n); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("L(16,15) = %s, want 1", got)
	}
	// L(31) = (31-1)/15 = 2
	if got := L(big.NewInt(31), n); got.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("L(31,15) = %s, want 2", got)
	}
	// L(46) = (46-1)/15 = 3
	if got := L(big.NewInt(46), n); got.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("L(46,15) = %s, want 3", got)
	}
	// L(1) = (1-1)/15 = 0
	if got := L(big.NewInt(1), n); got.Sign() != 0 {
		t.Fatalf("L(1,15) = %s, want 0", got)
	}
}

func TestEncryptRejectsNegativeMessage(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	// Negative values should be rejected or normalized modulo N.
	c, _, err := sk.Encrypt(nil, big.NewInt(-5))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sk.Decrypt(c)
	if err != nil {
		t.Fatal(err)
	}
	// -5 mod N should decrypt correctly (Encrypt normalizes).
	expected := new(big.Int).Mod(big.NewInt(-5), sk.N)
	if got.Cmp(expected) != 0 {
		t.Fatalf("negative message: got %s, want %s", got, expected)
	}
}

func TestUncheckedHelpersAcceptValidCiphertexts(t *testing.T) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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
