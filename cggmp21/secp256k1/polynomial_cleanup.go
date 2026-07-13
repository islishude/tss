package secp256k1

import (
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
)

func clearSecpPolynomial(poly shamir.Polynomial) {
	for i := range poly {
		poly[i] = secp.ScalarZero()
	}
}
