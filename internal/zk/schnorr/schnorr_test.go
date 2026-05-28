package schnorr

import (
	"bytes"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestProof(t *testing.T) {
	secret, err := secp.RandomScalar(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, public, err := Prove([]byte("test"), secret.BigInt())
	if err != nil {
		t.Fatal(err)
	}
	if !Verify([]byte("test"), public, proof) {
		t.Fatal("proof did not verify")
	}
	if Verify([]byte("other"), public, proof) {
		t.Fatal("proof verified with wrong domain")
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatal("proof encoding is not deterministic")
	}
	decoded, err := UnmarshalProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify([]byte("test"), public, decoded) {
		t.Fatal("decoded proof did not verify")
	}
	if _, err := UnmarshalProof([]byte(`{"commitment":"x"}`)); err == nil {
		t.Fatal("JSON proof decoded")
	}
	if _, err := UnmarshalProof(append(raw, 0)); err == nil {
		t.Fatal("proof with trailing byte decoded")
	}
	malformed := *proof
	malformed.Commitment = []byte{0x02}
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("malformed commitment encoded")
	}
	malformed = *proof
	malformed.Response = append([]byte{0}, proof.Response...)
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("malformed response encoded")
	}
}

func FuzzProofUnmarshal(f *testing.F) {
	secret, err := secp.RandomScalar(nil)
	if err != nil {
		f.Fatal(err)
	}
	proof, _, err := Prove([]byte("test"), secret.BigInt())
	if err != nil {
		f.Fatal(err)
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitment":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalProof(data)
	})
}
