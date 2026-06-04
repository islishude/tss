package secp256k1

import (
	"math/big"
	"testing"
)

func TestGPrecomputed(t *testing.T) {
	// G must be a finite point.
	if G.Inf != 0 {
		t.Fatal("G has Inf != 0, expected finite generator point")
	}

	// G must lie on the secp256k1 curve.
	if !IsOnCurve(G) {
		t.Fatal("G is not on the secp256k1 curve")
	}

	// G.x and G.y must match the SEC 2 standard values.
	wantX := FieldElementFromBigInt(mustHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
	wantY := FieldElementFromBigInt(mustHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))
	if !G.X.Equal(wantX) {
		t.Errorf("G.X mismatch:\n  got  %x\n  want %x", G.X.Bytes(), wantX.Bytes())
	}
	if !G.Y.Equal(wantY) {
		t.Errorf("G.Y mismatch:\n  got  %x\n  want %x", G.Y.Bytes(), wantY.Bytes())
	}

	// n * G must be infinity (G has order n).
	order := Order()
	nG := ScalarMult(G, ScalarFromBigInt(order))
	if nG.Inf == 0 {
		t.Fatal("n * G should be point at infinity")
	}
}

func mustHex(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex: " + s)
	}
	return x
}
