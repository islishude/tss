package secp256k1

import (
	"crypto/rand"
	"crypto/sha256"
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
