package schnorr

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
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
		p, err := UnmarshalProof(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, (*Proof).MarshalBinary, UnmarshalProof)
	})
}

func TestProofRejectsInvalidInputs(t *testing.T) {
	if _, _, err := Prove([]byte("test"), nil); err == nil {
		t.Fatal("Prove accepted nil secret")
	}
	if _, _, err := Prove([]byte("test"), big.NewInt(0)); err == nil {
		t.Fatal("Prove accepted zero secret")
	}

	secret, err := secp.RandomScalar(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, public, err := Prove([]byte("test"), secret.BigInt())
	if err != nil {
		t.Fatal(err)
	}
	if Verify([]byte("test"), public, nil) {
		t.Fatal("Verify accepted nil proof")
	}
	if Verify([]byte("test"), []byte{0x02}, proof) {
		t.Fatal("Verify accepted malformed public key")
	}
	malformed := *proof
	malformed.Commitment = []byte{0x02}
	if Verify([]byte("test"), public, &malformed) {
		t.Fatal("Verify accepted malformed commitment")
	}
	malformed = *proof
	malformed.Response = append([]byte{0}, proof.Response...)
	if Verify([]byte("test"), public, &malformed) {
		t.Fatal("Verify accepted malformed response")
	}
}

func TestProofTamper(t *testing.T) {
	secret, err := secp.RandomScalar(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, public, err := Prove([]byte("test"), secret.BigInt())
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, err := secp.RandomScalar(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPublic, err := Prove([]byte("test"), otherSecret.BigInt())
	if err != nil {
		t.Fatal(err)
	}
	if Verify([]byte("test"), otherPublic, proof) {
		t.Fatal("proof verified against wrong public key")
	}
	tampered := &Proof{
		Commitment: append([]byte(nil), proof.Commitment...),
		Response:   append([]byte(nil), proof.Response...),
	}
	tampered.Commitment[len(tampered.Commitment)-1] ^= 1
	if Verify([]byte("test"), public, tampered) {
		t.Fatal("proof verified with tampered commitment")
	}
	tampered = &Proof{
		Commitment: append([]byte(nil), proof.Commitment...),
		Response:   append([]byte(nil), proof.Response...),
	}
	tampered.Response[len(tampered.Response)-1] ^= 1
	if Verify([]byte("test"), public, tampered) {
		t.Fatal("proof verified with tampered response")
	}
}

func TestProofUnmarshalRejectsWrongFieldSet(t *testing.T) {
	validCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	if err != nil {
		t.Fatal(err)
	}
	validResponse := secp.ScalarFromBigInt(big.NewInt(2)).Bytes()
	for _, tc := range []struct {
		name    string
		version uint16
		fields  []wire.Field
	}{
		{name: "wrong version", version: proofVersion + 1, fields: []wire.Field{
			{Tag: proofFieldCommitment, Value: validCommitment},
			{Tag: proofFieldResponse, Value: validResponse},
		}},
		{name: "missing response", version: proofVersion, fields: []wire.Field{
			{Tag: proofFieldCommitment, Value: validCommitment},
		}},
		{name: "extra field", version: proofVersion, fields: []wire.Field{
			{Tag: proofFieldCommitment, Value: validCommitment},
			{Tag: proofFieldResponse, Value: validResponse},
			{Tag: 99, Value: []byte{1}},
		}},
		{name: "wrong response tag", version: proofVersion, fields: []wire.Field{
			{Tag: proofFieldCommitment, Value: validCommitment},
			{Tag: 99, Value: validResponse},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := wire.MarshalFields(tc.version, proofWireType, tc.fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalProof(raw); err == nil {
				t.Fatal("malformed proof field set decoded")
			}
		})
	}
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
}
