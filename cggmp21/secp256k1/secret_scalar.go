package secp256k1

import (
	"errors"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

func newSecpSecretScalar(data []byte) (*secret.Scalar, error) {
	if _, err := secp.ScalarFromBytes(data); err != nil {
		return nil, err
	}
	return secret.NewScalar(data, secp.ScalarSize)
}

func newSecpSecretScalarAllowZero(data []byte) (*secret.Scalar, error) {
	if _, err := secp.ScalarFromBytesAllowZero(data); err != nil {
		return nil, err
	}
	return secret.NewScalar(data, secp.ScalarSize)
}

func secpSecretScalarFromScalar(x secp.Scalar) (*secret.Scalar, error) {
	if x.IsZero() {
		return nil, errors.New("zero secret scalar")
	}
	raw := x.Bytes()
	defer clear(raw)
	return newSecpSecretScalar(raw)
}

func secpSecretScalarFromScalarAllowZero(x secp.Scalar) (*secret.Scalar, error) {
	raw := x.Bytes()
	defer clear(raw)
	return newSecpSecretScalarAllowZero(raw)
}

func secpScalarFromSecret(s *secret.Scalar) (secp.Scalar, error) {
	if s == nil {
		return secp.Scalar{}, errors.New("nil secret scalar")
	}
	raw := s.FixedBytes()
	defer clear(raw)
	return secp.ScalarFromBytes(raw)
}

func secpScalarFromSecretAllowZero(s *secret.Scalar) (secp.Scalar, error) {
	if s == nil {
		return secp.Scalar{}, errors.New("nil secret scalar")
	}
	raw := s.FixedBytes()
	defer clear(raw)
	return secp.ScalarFromBytesAllowZero(raw)
}

func validateSecretScalarStrict(x *secret.Scalar) error {
	if _, err := secpScalarFromSecret(x); err != nil {
		return err
	}
	return nil
}

func validateSecretScalarAllowZero(x *secret.Scalar) error {
	if _, err := secpScalarFromSecretAllowZero(x); err != nil {
		return err
	}
	return nil
}
