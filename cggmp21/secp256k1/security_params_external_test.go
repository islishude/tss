package secp256k1_test

import (
	"testing"

	cggmp "github.com/islishude/tss/cggmp21/secp256k1"
)

func TestSecurityParamsPublicAliasWireAPI(t *testing.T) {
	t.Parallel()

	params := cggmp.SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
	raw, err := params.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cggmp.UnmarshalSecurityParams(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != params {
		t.Fatalf("decoded params = %+v, want %+v", decoded, params)
	}
}
