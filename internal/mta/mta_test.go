package mta

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestMTAProductShares(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	startDomain := []byte("start")
	responseDomain := []byte("response")
	start, err := Start(nil, startDomain, a, &sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	response, betaShare, err := Respond(nil, startDomain, responseDomain, *start, b, bCommit, &sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	alphaShare, err := Finish(startDomain, responseDomain, *start, *response, bCommit, sk)
	if err != nil {
		t.Fatal(err)
	}
	got := new(big.Int).Add(alphaShare, betaShare)
	got.Mod(got, secp.Order())
	want := new(big.Int).Mul(a, b)
	want.Mod(want, secp.Order())
	if got.Cmp(want) != 0 {
		t.Fatalf("alpha+beta = %s, want %s", got, want)
	}
	response.Proof[0] ^= 1
	if _, err := Finish(startDomain, responseDomain, *start, *response, bCommit, sk); err == nil {
		t.Fatal("tampered response proof verified")
	}
}
