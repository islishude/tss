package secp256k1

import (
	"errors"
	"fmt"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

const secpScalarSize = 32

func newSecpSecretScalar(data []byte) (*secret.Scalar, error) {
	if len(data) != secpScalarSize {
		return nil, fmt.Errorf("secp256k1 secret scalar must be %d bytes", secpScalarSize)
	}
	if _, err := secp.ScalarFromBytes(data); err != nil {
		return nil, err
	}
	return secret.NewScalar(data, secpScalarSize)
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
	if s.FixedLen() != secpScalarSize {
		return nil, fmt.Errorf("secp256k1 secret scalar has length %d, want %d", s.FixedLen(), secpScalarSize)
	}
	out := s.FixedBytes()
	if _, err := secp.ScalarFromBytes(out); err != nil {
		return nil, err
	}
	return out, nil
}

func secpScalarFromSecret(s *secret.Scalar) (secp.Scalar, error) {
	out, err := secpSecretScalarBytes(s)
	if err != nil {
		return secp.Scalar{}, err
	}
	return secp.ScalarFromBytes(out)
}

func secpSecretBig(s *secret.Scalar) (*big.Int, error) {
	scalar, err := secpScalarFromSecret(s)
	if err != nil {
		return nil, err
	}
	return scalar.BigInt(), nil
}

func cloneSecpSecretScalar(s *secret.Scalar) *secret.Scalar {
	if s == nil {
		return nil
	}
	out, err := secret.NewScalar(s.FixedBytes(), s.FixedLen())
	if err != nil {
		return nil
	}
	return out
}
