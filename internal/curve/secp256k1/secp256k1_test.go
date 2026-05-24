package secp256k1

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestBasePointEncoding(t *testing.T) {
	enc, err := PointBytes(G)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PointFromBytes(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(got, G) {
		t.Fatal("base point round trip mismatch")
	}
}

func TestECDSASignVerify(t *testing.T) {
	secret, err := RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := ScalarBaseMult(secret)
	digest := sha256.Sum256([]byte("test"))
	r, s, err := SignECDSA(rand.Reader, digest[:], secret, true)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyECDSA(pub, digest[:], r, s) {
		t.Fatal("signature did not verify")
	}
}

func TestFiatScalarArithmeticMatchesBigInt(t *testing.T) {
	a := ScalarFromBig(big.NewInt(7))
	b := ScalarFromBig(big.NewInt(11))
	got := ScalarMul(ScalarAdd(a, b), b).Big()
	want := new(big.Int).Mul(big.NewInt(18), big.NewInt(11))
	want.Mod(want, N)
	if got.Cmp(want) != 0 {
		t.Fatalf("fiat scalar arithmetic mismatch: got %s want %s", got, want)
	}
	inv, err := ScalarInvert(b)
	if err != nil {
		t.Fatal(err)
	}
	if ScalarMul(b, inv).Big().Cmp(big.NewInt(1)) != 0 {
		t.Fatal("fiat scalar inversion failed")
	}
}

func TestFiatFieldArithmeticMatchesBigInt(t *testing.T) {
	a := FieldElementFromBig(big.NewInt(7))
	b := FieldElementFromBig(big.NewInt(11))
	got := FieldSquare(FieldAdd(a, b)).Big()
	want := new(big.Int).Mul(big.NewInt(18), big.NewInt(18))
	want.Mod(want, P)
	if got.Cmp(want) != 0 {
		t.Fatalf("fiat field arithmetic mismatch: got %s want %s", got, want)
	}
}
