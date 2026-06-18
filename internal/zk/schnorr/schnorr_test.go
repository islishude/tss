package schnorr

import (
	"bytes"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func testSecretScalar(t *testing.T, value uint64) *secret.Scalar {
	t.Helper()
	scalar := secp.ScalarFromUint64(value)
	out, err := secret.NewScalar(scalar.Bytes(), secp.ScalarSize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.Destroy)
	return out
}

func TestProof(t *testing.T) {
	t.Parallel()

	proof, public, err := Prove([]byte("test"), testSecretScalar(t, 13))
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

	proof, public, err := Prove([]byte("test"), testSecretScalar(t, 13))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("prove rejects invalid secret", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name   string
			secret *secret.Scalar
		}{
			{name: "nil", secret: nil},
			{name: "wrong width", secret: func() *secret.Scalar {
				out, err := secret.NewScalar([]byte{1}, secp.ScalarSize-1)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(out.Destroy)
				return out
			}()},
			{name: "zero", secret: func() *secret.Scalar {
				out, err := secret.NewScalar(make([]byte, secp.ScalarSize), secp.ScalarSize)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(out.Destroy)
				return out
			}()},
			{name: "out of range", secret: func() *secret.Scalar {
				order := secp.Order().FillBytes(make([]byte, secp.ScalarSize))
				out, err := secret.NewScalar(order, secp.ScalarSize)
				clear(order)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(out.Destroy)
				return out
			}()},
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

	proof, public, err := Prove([]byte("test"), testSecretScalar(t, 13))
	if err != nil {
		t.Fatal(err)
	}
	_, otherPublic, err := Prove([]byte("test"), testSecretScalar(t, 17))
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

	validCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarOne()))
	if err != nil {
		t.Fatal(err)
	}
	validResponse := secp.ScalarFromUint64(2).Bytes()
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
