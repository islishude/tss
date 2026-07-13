package secp256k1

import (
	"reflect"
	"testing"
)

// Composite wire objects with non-trivial validation remain pointers so a
// missing field cannot be confused with a zero-valued nested record.
func TestCGGMP21CompositeWireFieldsUsePointers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		typ    reflect.Type
		fields []string
	}{
		{typ: reflect.TypeFor[presignRound1Payload](), fields: []string{"PaillierPublicKey"}},
		{typ: reflect.TypeFor[auxInfoRevealPayload](), fields: []string{"PaillierPublicKey", "RingPedersenParams", "RingPedersenProof"}},
		{typ: reflect.TypeFor[figure6ProofPayload](), fields: []string{"Proof"}},
		{typ: reflect.TypeFor[keyShareState](), fields: []string{"Secret", "PaillierPrivateKey", "ShareProof", "Epoch"}},
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
