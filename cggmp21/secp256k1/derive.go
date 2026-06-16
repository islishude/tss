package secp256k1

import (
	"fmt"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// DerivePublicKey applies a secp256k1 additive scalar shift to publicKey.
func DerivePublicKey(publicKey, additiveShift []byte) ([]byte, error) {
	base, err := secp.PointFromBytes(publicKey)
	if err != nil {
		return nil, err
	}
	if len(additiveShift) == 0 {
		return secp.PointBytes(base)
	}
	shift, err := secp.ScalarFromBytesAllowZero(additiveShift)
	if err != nil {
		return nil, fmt.Errorf("invalid additive shift: %w", err)
	}
	if shift.IsZero() {
		return secp.PointBytes(base)
	}
	return secp.PointBytes(secp.Add(base, secp.ScalarBaseMult(shift)))
}
