package tss

import (
	"bytes"
	"slices"
	"testing"
)

func TestSigningContextCanonicalBinaryEncoding(t *testing.T) {
	t.Parallel()
	context := testSigningContext()
	raw1, err := context.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := context.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("signing context encoding is not deterministic")
	}
	decoded, err := UnmarshalSigningContext(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.KeyID != context.KeyID ||
		decoded.ChainID != context.ChainID ||
		decoded.PolicyDomain != context.PolicyDomain ||
		decoded.MessageDomain != context.MessageDomain ||
		decoded.Derivation.Scheme != context.Derivation.Scheme ||
		decoded.Derivation.InvalidChildMode != context.Derivation.InvalidChildMode ||
		!slices.Equal(decoded.Derivation.Path, context.Derivation.Path) ||
		!slices.Equal(decoded.Derivation.ResolvedPath, context.Derivation.ResolvedPath) {
		t.Fatal("signing context changed after round trip")
	}
	if err := decoded.UnmarshalBinary(append(raw1, 0)); err == nil {
		t.Fatal("signing context accepted trailing byte")
	}
}

func testSigningContext() SigningContext {
	return SigningContext{
		KeyID:   "key-1",
		ChainID: "chain-1",
		Derivation: DerivationRequest{
			Scheme:           DerivationSchemeBIP32Secp256k1,
			Path:             DerivationPath{1, 2},
			InvalidChildMode: SkipInvalidChild,
			ResolvedPath:     DerivationPath{1, 3},
		},
		PolicyDomain:  "policy",
		MessageDomain: "message",
	}
}
