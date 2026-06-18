package mta

import (
	"errors"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

const messageVersion = 1

func randomSecretScalar(reader io.Reader) (*secret.Scalar, error) {
	x, err := secp.RandomScalar(reader)
	if err != nil {
		return nil, err
	}
	return secret.NewScalar(x.Bytes(), secp.ScalarSize)
}

func secpScalarFromSecret(x *secret.Scalar) (secp.Scalar, error) {
	if x == nil {
		return secp.Scalar{}, errors.New("nil secret scalar")
	}
	fixed := x.FixedBytes()
	defer clear(fixed)
	return secp.ScalarFromBytes(fixed)
}

func mustSecpScalar(x *secret.Scalar) secp.Scalar {
	out, err := secpScalarFromSecret(x)
	if err != nil {
		panic("mta: invalid internal secret scalar")
	}
	return out
}

func validatePositiveIntegerBytes(in []byte) error {
	if len(in) == 0 {
		return errors.New("empty integer")
	}
	if in[0] == 0 {
		return errors.New("non-minimal integer encoding")
	}
	if new(big.Int).SetBytes(in).Sign() <= 0 {
		return errors.New("integer must be positive")
	}
	return nil
}
