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
		"factor_response":  4096, // Pi-fac responses may contain a product of two moduli.
		"paillier_signed":  2048, // same as above
		// Setup-less proofs use one repetition per challenge bit (256 at the
		// production profile), while the setup proofs retain 128 repetitions.
		"proof_rounds": affGStarMaxRounds,
	}
}

func zkFrameLimits(maxTotalBytes int) wire.FrameLimits {
	return wire.FrameLimits{
		MaxTotalBytes: maxTotalBytes,
		MaxFields:     tss.DefaultMaxWireFields,
		MaxFieldBytes: maxTotalBytes,
	}
}
