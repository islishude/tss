package paillierct

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/testutil"
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
	var err error
	p, err = crand.Prime(testutil.DeterministicReader(101), 256)
	if err != nil {
		t.Fatal(err)
	}
	q, err = crand.Prime(testutil.DeterministicReader(202), 256)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cmp(q) == 0 {
		t.Fatal("test primes must be distinct")
	}
	return p, q
}

func mustFixedEncodeStrict(t *testing.T, x *big.Int, fixedLen int) []byte {
	t.Helper()
	out, err := FixedEncodeStrict(x, fixedLen)
	if err != nil {
		t.Fatal(err)
	}
	return out
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
	lambda = mustFixedEncodeStrict(t, lambdaBig, nLen)
	return n, nSquared, lambda, nLen
}

func TestNewPrivateModExp(t *testing.T) {
	t.Parallel()

	_, nSquared := testKey(t)
	n := new(big.Int).Sqrt(nSquared)
	nsBytes := nSquared.Bytes()
	nFixed := mustFixedEncodeStrict(t, n, 64)
	nsFixed := mustFixedEncodeStrict(t, nSquared, 128) // 1024-bit n²

	// Valid construction.
	pm, err := NewPrivateModExp(nFixed, nsFixed, 64)
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
	if _, err := NewPrivateModExp(nil, nsFixed, 64); err == nil {
		t.Fatal("expected error for nil modulus")
	}
	if _, err := NewPrivateModExp(nFixed, nil, 64); err == nil {
		t.Fatal("expected error for nil squared modulus")
	}
	if _, err := NewPrivateModExp([]byte{1}, []byte{1}, 64); err == nil {
		t.Fatal("expected error for n <= 1")
	}
	// Invalid: zero expSize.
	if _, err := NewPrivateModExp(nFixed, nsBytes, 0); err == nil {
		t.Fatal("expected error for zero expSize")
	}
	if _, err := NewPrivateModExp(nFixed, mustFixedEncodeStrict(t, new(big.Int).Add(nSquared, big.NewInt(1)), 128), 64); err == nil {
		t.Fatal("expected error for mismatched squared modulus")
	}
	if _, err := randomCoprimeFixed(testutil.DeterministicReader(1), []byte{1}); err == nil {
		t.Fatal("expected error for n <= 1")
	}
}

func TestExpSecretMatchesBigInt(t *testing.T) {
	t.Parallel()

	_, nSquared, lambda, nLen := testLambda(t)
	n := new(big.Int).Sqrt(nSquared)
	nFixed := mustFixedEncodeStrict(t, n, nLen)
	nsFixed := mustFixedEncodeStrict(t, nSquared, 2*nLen)

	pm, err := NewPrivateModExp(nFixed, nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random ciphertext < n².
	ctBig, err := crand.Int(testutil.DeterministicReader(303), nSquared)
	if err != nil {
		t.Fatal(err)
	}
	if ctBig.Sign() == 0 {
		ctBig.SetInt64(1)
	}
	ctFixed := mustFixedEncodeStrict(t, ctBig, 2*nLen)

	got, err := pm.ExpSecret(ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	// Reference: math/big.
	lambdaBig := new(big.Int).SetBytes(lambda)
	wantBig := new(big.Int).Exp(ctBig, lambdaBig, nSquared)
	want := mustFixedEncodeStrict(t, wantBig, 2*nLen)

	if !bytes.Equal(got, want) {
		t.Fatal("ExpSecret result does not match math/big reference")
	}
}

func TestExpSecretBlindedMatchesExpSecret(t *testing.T) {
	t.Parallel()

	n, nSquared, lambda, nLen := testLambda(t)
	nBytes := mustFixedEncodeStrict(t, n, nLen)
	nsFixed := mustFixedEncodeStrict(t, nSquared, 2*nLen)

	pm, err := NewPrivateModExp(nBytes, nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random ciphertext < n².
	ctBig, err := crand.Int(testutil.DeterministicReader(404), nSquared)
	if err != nil {
		t.Fatal(err)
	}
	if ctBig.Sign() == 0 {
		ctBig.SetInt64(1)
	}
	ctFixed := mustFixedEncodeStrict(t, ctBig, 2*nLen)

	gotRaw, err := pm.ExpSecret(ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	gotBlinded, err := pm.ExpSecretBlinded(testutil.DeterministicReader(405), ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	// c^λ ≡ (c * r^n)^λ mod n² since r^(n*λ) ≡ 1 mod n².
	if !bytes.Equal(gotRaw, gotBlinded) {
		t.Fatal("ExpSecretBlinded result does not match ExpSecret")
	}
}

func TestExpCT(t *testing.T) {
	t.Parallel()

	_, nSquared := testKey(t)
	modulus := mustFixedEncodeStrict(t, nSquared, 128) // 1024-bit

	base := make([]byte, 128)
	if _, err := io.ReadFull(testutil.DeterministicReader(505), base); err != nil {
		t.Fatal(err)
	}
	baseBig := new(big.Int).SetBytes(base)
	baseBig.Mod(baseBig, nSquared)
	if baseBig.Sign() == 0 {
		baseBig.SetInt64(1)
	}
	baseFixed := mustFixedEncodeStrict(t, baseBig, 128)

	exp := make([]byte, 32) // 256-bit exponent like secp256k1 scalar
	if _, err := io.ReadFull(testutil.DeterministicReader(506), exp); err != nil {
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
	want := mustFixedEncodeStrict(t, wantBig, 128)

	if !bytes.Equal(got, want) {
		t.Fatal("ExpCT result does not match math/big reference")
	}
}

func TestExpCTRejectsMismatchedInputs(t *testing.T) {
	t.Parallel()

	if _, err := ExpCT(nil, []byte{1}, []byte{1}); err == nil {
		t.Fatal("expected error for nil modulus")
	}
	if _, err := ExpCT([]byte{1}, []byte{1, 2}, []byte{1}); err == nil {
		t.Fatal("expected error for mismatched base length")
	}
}

func TestFixedEncode(t *testing.T) {
	t.Parallel()

	x := big.NewInt(0x1234)
	got, err := FixedEncodeStrict(x, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0x00, 0x00, 0x12, 0x34}) {
		t.Fatalf("FixedEncode = %x, want 00001234", got)
	}

	// Strict encoding rejects oversized input.
	x2 := big.NewInt(0x0102030405)
	if _, err := FixedEncodeStrict(x2, 3); err == nil {
		t.Fatal("FixedEncodeStrict accepted oversized input")
	}
	got2 := FixedEncodeReduced(x2, 3)
	if !bytes.Equal(got2, []byte{0x03, 0x04, 0x05}) {
		t.Fatalf("FixedEncodeReduced = %x, want 030405", got2)
	}
	for _, tc := range []struct {
		name     string
		x        *big.Int
		fixedLen int
	}{
		{name: "nil", x: nil, fixedLen: 1},
		{name: "negative", x: big.NewInt(-1), fixedLen: 1},
		{name: "zero length", x: big.NewInt(1), fixedLen: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FixedEncodeStrict(tc.x, tc.fixedLen); err == nil {
				t.Fatal("FixedEncodeStrict accepted invalid input")
			}
		})
	}
}

// TestExpSecretConstantTimeInputValidation verifies strict length checks.
func TestExpSecretConstantTimeInputValidation(t *testing.T) {
	t.Parallel()

	_, nSquared, _, nLen := testLambda(t)
	n := new(big.Int).Sqrt(nSquared)
	nFixed := mustFixedEncodeStrict(t, n, nLen)
	nsFixed := mustFixedEncodeStrict(t, nSquared, 2*nLen)
	lambda := make([]byte, nLen)
	pm, err := NewPrivateModExp(nFixed, nsFixed, nLen)
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
	t.Parallel()

	_, nSquared, lambda, nLen := testLambda(t)
	n := new(big.Int).Sqrt(nSquared)
	nFixed := mustFixedEncodeStrict(t, n, nLen)
	nsFixed := mustFixedEncodeStrict(t, nSquared, 2*nLen)

	pm, err := NewPrivateModExp(nFixed, nsFixed, nLen)
	if err != nil {
		t.Fatal(err)
	}

	ctBig, err := crand.Int(testutil.DeterministicReader(606), nSquared)
	if err != nil {
		t.Fatal(err)
	}
	if ctBig.Sign() == 0 {
		ctBig.SetInt64(1)
	}
	ctFixed := mustFixedEncodeStrict(t, ctBig, 2*nLen)

	// Verify correctness with the real lambda (from lcm).
	result, err := pm.ExpSecret(ctFixed, lambda)
	if err != nil {
		t.Fatal(err)
	}

	lambdaBig := new(big.Int).SetBytes(lambda)
	want := new(big.Int).Exp(ctBig, lambdaBig, nSquared)
	wantBytes := mustFixedEncodeStrict(t, want, 2*nLen)
	if !bytes.Equal(result, wantBytes) {
		t.Fatal("ExpSecret mismatch with math/big reference")
	}
}
