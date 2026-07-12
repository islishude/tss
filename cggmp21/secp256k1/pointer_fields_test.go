package secp256k1

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestCGGMP21CompositeWireFieldsUsePointers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ    reflect.Type
		fields []string
	}{
		{
			typ: reflect.TypeFor[keygenCommitmentsPayload](),
			fields: []string{
				"PaillierPublicKey",
				"PaillierProof",
				"RingPedersenParams",
				"RingPedersenProof",
			},
		},
		{
			typ: reflect.TypeFor[refreshCommitmentsPayload](),
			fields: []string{
				"PaillierPublicKey",
				"PaillierProof",
				"RingPedersenParams",
				"RingPedersenProof",
			},
		},
		{
			typ:    reflect.TypeFor[presignRound1Payload](),
			fields: []string{"PaillierPublicKey"},
		},
		{
			typ: reflect.TypeFor[presignVerificationEntry](),
			fields: []string{
				"PaillierPublicKey",
				"Delta",
			},
		},
	}

	for _, tc := range tests {
		for _, name := range tc.fields {
			field, ok := tc.typ.FieldByName(name)
			if !ok {
				t.Fatalf("%s.%s does not exist", tc.typ.Name(), name)
			}
			if field.Type.Kind() != reflect.Pointer {
				t.Fatalf("%s.%s has type %s, want pointer", tc.typ.Name(), name, field.Type)
			}
		}
	}
}

func TestCGGMP21PresignRound1PointerFieldRoundTrip(t *testing.T) {
	t.Parallel()

	publicKey := testPaillierPublicKey(65)
	gamma, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarOne()))
	if err != nil {
		t.Fatal(err)
	}
	payload := presignRound1Payload{
		Gamma:             gamma,
		EncK:              []byte{1},
		PaillierPublicKey: publicKey,
		PlanHash:          bytes.Repeat([]byte{0x42}, 32),
		KPoint:            bytes.Clone(gamma),
	}
	raw, err := payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalPresignRound1Payload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PaillierPublicKey == nil {
		t.Fatal("decoded Paillier public key is nil")
	}
	roundTrip, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, roundTrip) {
		t.Fatal("pointer field changed canonical presign round1 encoding")
	}
}

func TestCGGMP21PresignVerificationEntryCloneOwnsPointers(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	original := &presign.state.Verification.Entries[0]
	cloned := original.clone()
	defer (&presignVerificationContext{Entries: []presignVerificationEntry{cloned}}).destroy()

	if cloned.PaillierPublicKey == original.PaillierPublicKey {
		t.Fatal("cloned verification entry shares Paillier public key pointer")
	}
	if cloned.Delta == original.Delta {
		t.Fatal("cloned verification entry shares delta pointer")
	}

	cloned.PaillierPublicKey.N.Add(cloned.PaillierPublicKey.N, big.NewInt(2))
	cloned.Delta.Set(secp.ScalarFromUint64(7))
	if cloned.PaillierPublicKey.N.Cmp(original.PaillierPublicKey.N) == 0 {
		t.Fatal("mutating cloned Paillier public key changed original")
	}
	if cloned.Delta.Equal(*original.Delta) {
		t.Fatal("mutating cloned delta changed original")
	}
}

func TestCGGMP21PresignVerificationContextRejectsNilPointerFields(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()

	nilPublicKey := presign.state.Verification.clone()
	nilPublicKey.Entries[0].PaillierPublicKey = nil
	if err := validatePresignVerificationContext(presign.state.Signers, nilPublicKey, testLimits()); err == nil {
		t.Fatal("accepted nil presign verification Paillier public key")
	}
	nilPublicKey.destroy()

	nilDelta := presign.state.Verification.clone()
	nilDelta.Entries[0].Delta = nil
	if err := validatePresignVerificationContext(presign.state.Signers, nilDelta, testLimits()); err == nil {
		t.Fatal("accepted nil presign verification delta")
	}
	nilDelta.destroy()
}
