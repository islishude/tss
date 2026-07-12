package mta

import (
	"errors"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

func randomSecretScalar(reader io.Reader) (*secret.Scalar, error) {
	x, err := secp.RandomScalar(reader)
	if err != nil {
		return nil, err
	}
	return secret.NewScalar(x.Bytes(), secp.ScalarSize)
}

func randomWideMask(reader io.Reader, bits uint32) (*secret.SignedInt, error) {
	if bits == 0 {
		return nil, errors.New("wide mask bit length must be positive")
	}
	// One extra sign-capacity bit keeps the representation compatible with the
	// inclusive signed range used by the AffG proof implementation.
	fixedLen := int((bits + 8) / 8)
	encoded := make([]byte, fixedLen)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		clear(encoded)
		return nil, err
	}
	if excess := uint(fixedLen*8) - uint(bits); excess > 0 {
		encoded[0] &= byte(0xff >> excess)
	}
	defer clear(encoded)
	return secret.NewSignedInt(false, encoded, fixedLen)
}

func signedSecretScalarModOrder(value *secret.SignedInt) (secp.Scalar, error) {
	if value == nil || value.FixedLen() == 0 {
		return secp.Scalar{}, errors.New("nil or destroyed signed secret")
	}
	magnitude := value.FixedMagnitude()
	defer clear(magnitude)
	reduced := new(big.Int).SetBytes(magnitude)
	defer secret.ClearBigInt(reduced)
	reduced.Mod(reduced, secp.Order())
	out := secp.ScalarFromBigInt(reduced)
	negative, err := value.SelectBySign([]byte{0}, []byte{1})
	if err != nil {
		return secp.Scalar{}, err
	}
	defer clear(negative)
	if negative[0] == 1 {
		out = secp.ScalarNeg(out)
	}
	return out, nil
}

func secpScalarFromSecret(x *secret.Scalar) (secp.Scalar, error) {
	if x == nil {
		return secp.Scalar{}, errors.New("nil secret scalar")
	}
	fixed := x.FixedBytes()
	defer clear(fixed)
	return secp.ScalarFromBytes(fixed)
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
