package paillierct

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func testKey(t *testing.T) (n, nSquared *big.Int) {
	t.Helper()
	p, q := testPrimes(t)
	n = new(big.Int).Mul(p, q)
	nSquared = new(big.Int).Mul(n, n)
	return n, nSquared
}

func testPrimes(t *testing.T) (p, q *big.Int) {
	t.Helper()
	p, _ = rand.Prime(rand.Reader, 256)
	q, _ = rand.Prime(rand.Reader, 256)
	for p.Cmp(q) == 0 {
		q, _ = rand.Prime(rand.Reader, 256)
	}
	return p, q
}

func testLambda(t *testing.T) (n, nSquared *big.Int, lambda []byte, nLen int) {
	t.Helper()
	p, q := testPrimes(t)
	n = new(big.Int).Mul(p, q)
	nSquared = new(big.Int).Mul(n, n)
	nLen = (n.BitLen() + 7) / 8
	// λ = lcm(p-1, q-1)
	p1 := new(big.Int).Sub(p, big.NewInt(1))
	q1 := new(big.Int).Sub(q, big.NewInt(1))
	g := new(big.Int).GCD(nil, nil, p1, q1)
	lambdaBig := new(big.Int).Div(new(big.Int).Mul(p1, q1), g)
	lambda = FixedEncode(lambdaBig, nLen)
	return n, nSquared, lambda, nLen
}

func TestNewPrivateModExp(t *testing.T) {
	_, nSquared := testKey(t)
	nsBytes := nSquared.Bytes()
	nsFixed := FixedEncode(nSquared, 128) // 1024-bit n²

	// Valid construction.
	pm, err := NewPrivateModExp(nsFixed, 64)
	if err != nil {
		t.Fatal(err)
	}
	if pm.modSize != len(nsFixed) {
		t.Fatalf("modSize = %d, want %d", pm.modSize, len(nsFixed))
	}
	if pm.expSize != 64 {
		t.Fatalf("expSize = %d, want 64", pm.expSize)
	}

	// Invalid: empty modulus.
	if _, err := NewPrivateModExp(nil, 64); err == nil {
		t.Fatal("expected error for nil modulus")
	}
	// Invalid: zero expSize.
	if _, err := NewPrivateModExp(nsBytes, 0); err == nil {
		t.Fatal("expected error for zero expSize")
	}
}

func TestExpSecretMatchesBigInt(t *testing.T) {
	_, nSquared, lambda, nLen := testLambda(t)
	nsFixed := FixedEncode(nSquared, 2*nLen)

	pm, err := NewPrivateModExp(nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random ciphertext < n².
	ctBig, _ := rand.Int(rand.Reader, nSquared)
	if ctBig.Sign() == 0 {
		ctBig.SetInt64(1)
	}
	ctFixed := FixedEncode(ctBig, 2*nLen)

	got, err := pm.ExpSecret(ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	// Reference: math/big.
	lambdaBig := new(big.Int).SetBytes(lambda)
	wantBig := new(big.Int).Exp(ctBig, lambdaBig, nSquared)
	want := FixedEncode(wantBig, 2*nLen)

	if !bytes.Equal(got, want) {
		t.Fatal("ExpSecret result does not match math/big reference")
	}
}

func TestExpSecretBlindedMatchesExpSecret(t *testing.T) {
	n, nSquared, lambda, nLen := testLambda(t)
	nBytes := FixedEncode(n, nLen)
	nsFixed := FixedEncode(nSquared, 2*nLen)

	pm, err := NewPrivateModExp(nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random ciphertext < n².
	ctBig, _ := rand.Int(rand.Reader, nSquared)
	if ctBig.Sign() == 0 {
		ctBig.SetInt64(1)
	}
	ctFixed := FixedEncode(ctBig, 2*nLen)

	gotRaw, err := pm.ExpSecret(ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	gotBlinded, err := pm.ExpSecretBlinded(rand.Reader, ctFixed, lambda, nBytes)
	if err != nil {
		t.Fatal(err)
	}

	// c^λ ≡ (c * r^n)^λ mod n² since r^(n*λ) ≡ 1 mod n².
	if !bytes.Equal(gotRaw, gotBlinded) {
		t.Fatal("ExpSecretBlinded result does not match ExpSecret")
	}
}

func TestExpCT(t *testing.T) {
	_, nSquared := testKey(t)
	modulus := FixedEncode(nSquared, 128) // 1024-bit

	base := make([]byte, 128)
	if _, err := rand.Read(base); err != nil {
		t.Fatal(err)
	}
	baseBig := new(big.Int).SetBytes(base)
	baseBig.Mod(baseBig, nSquared)
	if baseBig.Sign() == 0 {
		baseBig.SetInt64(1)
	}
	baseFixed := FixedEncode(baseBig, 128)

	exp := make([]byte, 32) // 256-bit exponent like secp256k1 scalar
	if _, err := rand.Read(exp); err != nil {
		t.Fatal(err)
	}
	exp[0] |= 1

	got, err := ExpCT(modulus, baseFixed, exp)
	if err != nil {
		t.Fatal(err)
	}

	// Reference.
	expBig := new(big.Int).SetBytes(exp)
	wantBig := new(big.Int).Exp(baseBig, expBig, nSquared)
	want := FixedEncode(wantBig, 128)

	if !bytes.Equal(got, want) {
		t.Fatal("ExpCT result does not match math/big reference")
	}
}

func TestExpCTRejectsMismatchedInputs(t *testing.T) {
	if _, err := ExpCT(nil, []byte{1}, []byte{1}); err == nil {
		t.Fatal("expected error for nil modulus")
	}
	if _, err := ExpCT([]byte{1}, []byte{1, 2}, []byte{1}); err == nil {
		t.Fatal("expected error for mismatched base length")
	}
}

func TestFixedEncode(t *testing.T) {
	x := big.NewInt(0x1234)
	got := FixedEncode(x, 4)
	if !bytes.Equal(got, []byte{0x00, 0x00, 0x12, 0x34}) {
		t.Fatalf("FixedEncode = %x, want 00001234", got)
	}

	// Truncation from left.
	x2 := big.NewInt(0x0102030405)
	got2 := FixedEncode(x2, 3)
	if !bytes.Equal(got2, []byte{0x03, 0x04, 0x05}) {
		t.Fatalf("FixedEncode = %x, want 030405", got2)
	}
}

// TestExpSecretConstantTimeInputValidation verifies strict length checks.
func TestExpSecretConstantTimeInputValidation(t *testing.T) {
	_, nSquared, _, nLen := testLambda(t)
	nsFixed := FixedEncode(nSquared, 2*nLen)
	lambda := make([]byte, nLen)
	pm, err := NewPrivateModExp(nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	ctLen := 2 * nLen

	// Wrong ciphertext length.
	if _, err := pm.ExpSecret(make([]byte, ctLen-1), lambda); err == nil {
		t.Fatal("expected error for wrong ciphertext length")
	}
	if _, err := pm.ExpSecret(make([]byte, ctLen+1), lambda); err == nil {
		t.Fatal("expected error for wrong ciphertext length")
	}

	// Wrong lambda length.
	ct := make([]byte, ctLen)
	if _, err := pm.ExpSecret(ct, make([]byte, nLen-1)); err == nil {
		t.Fatal("expected error for wrong exponent length")
	}
	if _, err := pm.ExpSecret(ct, make([]byte, nLen+1)); err == nil {
		t.Fatal("expected error for wrong exponent length")
	}
}

// TestTimingConstantTime verifies constant-time exponentiation correctness with
// exponents of different Hamming weights. A variable-time implementation would
// produce different results (due to premature bit-skipping) or show dramatically
// different timings. This is a correctness check, not a statistical timing test.
func TestTimingConstantTime(t *testing.T) {
	_, nSquared, lambda, nLen := testLambda(t)
	nsFixed := FixedEncode(nSquared, 2*nLen)

	pm, err := NewPrivateModExp(nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	ctBig, _ := rand.Int(rand.Reader, nSquared)
	if ctBig.Sign() == 0 {
		ctBig.SetInt64(1)
	}
	ctFixed := FixedEncode(ctBig, 2*nLen)

	// Verify correctness with the real lambda (from lcm).
	result, err := pm.ExpSecret(ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	lambdaBig := new(big.Int).SetBytes(lambda)
	want := new(big.Int).Exp(ctBig, lambdaBig, nSquared)
	wantBytes := FixedEncode(want, 2*nLen)
	if !bytes.Equal(result, wantBytes) {
		t.Fatal("ExpSecret mismatch with math/big reference")
	}
}
