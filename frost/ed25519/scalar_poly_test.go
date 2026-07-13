package ed25519

import (
	"bytes"
	"errors"
	"io"
	"testing"

	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func TestFROSTRandomScalarPolynomialPartialReaderFailureReturnsNoMaterial(t *testing.T) {
	oneScalarThenPartial := make([]byte, 33)
	oneScalarThenPartial[31] = 1
	tests := []struct {
		name      string
		reader    *bytes.Reader
		threshold int
		constant  bool
	}{
		{
			name:      "generated coefficient then partial read",
			reader:    bytes.NewReader(oneScalarThenPartial),
			threshold: 2,
		},
		{
			name:      "copied constant then partial read",
			reader:    bytes.NewReader([]byte{0x01}),
			threshold: 2,
			constant:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var constant = edcurve.ScalarOne()
			defer constant.Set(edcurve.ScalarZero())
			if !tc.constant {
				constant = nil
			}
			coefficients, err := randomScalarPolynomial(tc.reader, tc.threshold, constant)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("partial reader error = %v, want unexpected EOF", err)
			}
			if coefficients != nil {
				clearScalars(coefficients)
				t.Fatal("partial reader failure returned secret polynomial material")
			}
		})
	}
}
