package schnorr

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestProof(t *testing.T) {
	t.Parallel()

	proof, public, err := Prove([]byte("test"), big.NewInt(13))
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

func TestProofRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	proof, public, err := Prove([]byte("test"), big.NewInt(13))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("prove rejects invalid secret", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name   string
			secret *big.Int
		}{
			{name: "nil", secret: nil},
			{name: "zero", secret: big.NewInt(0)},
		}
		for i := range tests {
			tc := tests[i]
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				if _, _, err := Prove([]byte("test"), tc.secret); err == nil {
					t.Fatal("Prove accepted invalid secret")
				}
			})
		}
	})

	t.Run("verify rejects malformed inputs", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name   string
			public []byte
			proof  *Proof
		}{
			{name: "nil proof", public: public, proof: nil},
			{name: "malformed public key", public: []byte{0x02}, proof: proof},
			{name: "malformed commitment", public: public, proof: func() *Proof {
				malformed := *proof
				malformed.Commitment = []byte{0x02}
				return &malformed
			}()},
			{name: "malformed response", public: public, proof: func() *Proof {
				malformed := *proof
				malformed.Response = append([]byte{0}, proof.Response...)
				return &malformed
			}()},
		}
		for i := range tests {
			tc := tests[i]
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				if Verify([]byte("test"), tc.public, tc.proof) {
					t.Fatal("Verify accepted malformed input")
				}
			})
		}
	})
}

func TestProofTamper(t *testing.T) {
	t.Parallel()

	proof, public, err := Prove([]byte("test"), big.NewInt(13))
	if err != nil {
		t.Fatal(err)
	}
	_, otherPublic, err := Prove([]byte("test"), big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		public []byte
		proof  *Proof
	}{
		{name: "wrong public key", public: otherPublic, proof: proof},
		{name: "tampered commitment", public: public, proof: func() *Proof {
			tampered := proof.Clone()
			tampered.Commitment[len(tampered.Commitment)-1] ^= 1
			return tampered
		}()},
		{name: "tampered response", public: public, proof: func() *Proof {
			tampered := proof.Clone()
			tampered.Response[len(tampered.Response)-1] ^= 1
			return tampered
		}()},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if Verify([]byte("test"), tc.public, tc.proof) {
				t.Fatal("tampered proof verified")
			}
		})
	}
}

func TestProofUnmarshalRejectsWrongFieldSet(t *testing.T) {
	t.Parallel()

	validCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	if err != nil {
		t.Fatal(err)
	}
	validResponse := secp.ScalarFromBigInt(big.NewInt(2)).Bytes()
	tests := []struct {
		name    string
		version uint16
		fields  []wire.Field
	}{
		{name: "wrong version", version: proofVersion + 1, fields: []wire.Field{
			{Tag: testutil.MustFieldTag(Proof{}, "Commitment"), Value: validCommitment},
			{Tag: testutil.MustFieldTag(Proof{}, "Response"), Value: validResponse},
		}},
		{name: "missing response", version: proofVersion, fields: []wire.Field{
			{Tag: testutil.MustFieldTag(Proof{}, "Commitment"), Value: validCommitment},
		}},
		{name: "extra field", version: proofVersion, fields: []wire.Field{
			{Tag: testutil.MustFieldTag(Proof{}, "Commitment"), Value: validCommitment},
			{Tag: testutil.MustFieldTag(Proof{}, "Response"), Value: validResponse},
			{Tag: 99, Value: []byte{1}},
		}},
		{name: "wrong response tag", version: proofVersion, fields: []wire.Field{
			{Tag: testutil.MustFieldTag(Proof{}, "Commitment"), Value: validCommitment},
			{Tag: 99, Value: validResponse},
		}},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
