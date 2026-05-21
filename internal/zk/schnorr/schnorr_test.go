package schnorr

import (
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestProof(t *testing.T) {
	secret, err := secp.RandomScalar(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, public, err := Prove([]byte("test"), secret)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify([]byte("test"), public, proof) {
		t.Fatal("proof did not verify")
	}
	if Verify([]byte("other"), public, proof) {
		t.Fatal("proof verified with wrong domain")
	}
}
