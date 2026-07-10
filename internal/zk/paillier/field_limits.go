package paillier

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// zkFieldLimits returns semantic field limits for ZK proof wire encoding.
// These are conservative upper bounds based on maximum security parameters.
func zkFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"paillier_modulus": 2048, // up to 8192-bit modulus (N^2 → 2048 bytes)
		"point":            65,   // secp256k1 uncompressed point
		"signed_response":  2048, // signed value in [-N, N^2] range
		"paillier_signed":  2048, // same as above
		"proof_rounds":     modulusProofRounds,
	}
}

func zkFrameLimits(maxTotalBytes int) wire.FrameLimits {
	return wire.FrameLimits{
		MaxTotalBytes: maxTotalBytes,
		MaxFields:     tss.DefaultMaxWireFields,
		MaxFieldBytes: maxTotalBytes,
	}
}
