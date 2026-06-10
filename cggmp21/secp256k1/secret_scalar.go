package secp256k1

import (
	"errors"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

func newSecpSecretScalar(data []byte) (*secret.Scalar, error) {
	if _, err := secp.ScalarFromBytes(data); err != nil {
		return nil, err
	}
	return secret.NewScalar(data, secp.ScalarSize)
}

func secpSecretScalarFromBig(x *big.Int) (*secret.Scalar, error) {
	if x == nil {
		return nil, errors.New("nil secret scalar")
	}
	return newSecpSecretScalar(scalarBytes(x))
}

func secpScalarFromSecret(s *secret.Scalar) (secp.Scalar, error) {
	if s == nil {
		return secp.Scalar{}, errors.New("nil secret scalar")
	}
	return secp.ScalarFromBytes(s.FixedBytes())
}

func secpSecretBig(s *secret.Scalar) (*big.Int, error) {
	scalar, err := secpScalarFromSecret(s)
	if err != nil {
		return nil, err
	}
	return scalar.BigInt(), nil
}

// scalarBytes encodes x as a fixed-length secp256k1 scalar in canonical
// big-endian form. x is reduced modulo the subgroup order before encoding.
//
// Precondition: x MUST be in [0, q) where q is the secp256k1 group order.
// All callers validate this through [validateScalarRangeAllowZero] or
// [validateScalarRangeStrict] during unmarshaling, or produce x through
// modular reduction (x.Mod(x, order)). A value outside this range is
// silently reduced by [secp.ScalarFromBigInt]; the validation at the
// unmarshal layer is the authoritative defense against out-of-range
// wire values.
func scalarBytes(x *big.Int) []byte {
	return secp.ScalarFromBigInt(x).Bytes()
}

// validateScalarRangeStrict checks that x is strictly positive and below the
// secp256k1 group order (0 < x < q). Used in payload marshal/unmarshal wrappers
// to complement wire-level bigpos validation (which cannot check the group order).
func validateScalarRangeStrict(x *big.Int) error {
	if x == nil {
		return errors.New("nil scalar")
	}
	if x.Sign() <= 0 {
		return errors.New("scalar must be strictly positive")
	}
	if x.Cmp(secp.Order()) >= 0 {
		return errors.New("scalar exceeds group order")
	}
	return nil
}

// validateScalarRangeAllowZero checks that x is non-negative and below the
// secp256k1 group order (0 <= x < q). Zero is allowed. It complements wire-level
// biguint validation for protocol fields where zero is a valid value (e.g.
// partial signature s_i before aggregation).
func validateScalarRangeAllowZero(x *big.Int) error {
	if x == nil {
		return errors.New("nil scalar")
	}
	if x.Sign() < 0 {
		return errors.New("scalar must not be negative")
	}
	if x.Cmp(secp.Order()) >= 0 {
		return errors.New("scalar exceeds group order")
	}
	return nil
}
