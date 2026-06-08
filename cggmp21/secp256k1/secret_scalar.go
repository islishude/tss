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

func secpSecretScalarBytes(s *secret.Scalar) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil secret scalar")
	}
	out := s.FixedBytes()
	// check if the bytes encode a valid scalar
	if _, err := secp.ScalarFromBytes(out); err != nil {
		return nil, err
	}
	return out, nil
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
func scalarBytes(x *big.Int) []byte {
	return secp.ScalarFromBigInt(x).Bytes()
}
