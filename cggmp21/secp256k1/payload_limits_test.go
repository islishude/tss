package secp256k1

import (
	"strings"
	"testing"
)

func TestPayloadDecodersEnforceMessageFrameLimit(t *testing.T) {
	t.Parallel()

	limits := testLimits()
	limits.Payload.MaxMessageBytes = 64
	oversized := make([]byte, limits.Payload.MaxMessageBytes+1)

	for name, decode := range map[string]func([]byte) error{
		"protocol payload": func(in []byte) error {
			var payload keygenSharePayload
			return payload.UnmarshalBinaryWithLimits(in, limits)
		},
		"keygen confirmation": func(in []byte) error {
			var confirmation KeygenConfirmation
			return confirmation.UnmarshalBinaryWithLimits(in, limits)
		},
	} {
		if err := decode(oversized); err == nil || !strings.Contains(err.Error(), "wire input too large") {
			t.Errorf("%s oversized decode got %v, want wire frame rejection", name, err)
		}
	}
}

func TestCGGMPFieldLimitsKeepFactorResponsesBounded(t *testing.T) {
	t.Parallel()
	if got := DefaultLimits().fieldLimits()["factor_response"]; got != maxFactorResponseBytes {
		t.Fatalf("factor response limit = %d, want %d", got, maxFactorResponseBytes)
	}
}
