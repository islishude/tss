package paillier

import (
	"errors"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
)

func signedSecretSecpScalar(x *secret.SignedInt) (secp.Scalar, error) {
	value, err := signedSecretBig(x)
	if err != nil {
		return secp.Scalar{}, err
	}
	defer secret.ClearBigInt(value)
	return secp.ScalarFromBigInt(value), nil
}

func resizeSignedSecret(x *secret.SignedInt, fixedLen int) (*secret.SignedInt, error) {
	value, err := signedSecretBig(x)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(value)
	return signedSecretFromBig(value, fixedLen)
}

func encRandomSecrets(pk *pai.PublicKey, message *secret.SignedInt, randomness *secret.Scalar) (*big.Int, error) {
	messageBig, err := signedSecretBig(message)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(messageBig)
	randomnessBig, err := secretScalarBig(randomness)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(randomnessBig)
	return EncRandom(pk, messageBig, randomnessBig)
}

func secretScalarFromBig(x *big.Int, fixedLen int) (*secret.Scalar, error) {
	if x == nil || x.Sign() < 0 || fixedLen <= 0 {
		return nil, errors.New("invalid non-negative secret integer")
	}
	if x.BitLen() > fixedLen*8 {
		return nil, errors.New("secret integer exceeds fixed width")
	}
	encoded, err := paillierct.FixedEncodeStrict(x, fixedLen)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return secret.NewScalar(encoded, fixedLen)
}

func secretScalarBig(x *secret.Scalar) (*big.Int, error) {
	if x == nil || x.FixedLen() == 0 {
		return nil, errors.New("invalid secret integer")
	}
	fixed := x.FixedBytes()
	defer clear(fixed)
	return new(big.Int).SetBytes(fixed), nil
}

func signedSecretFromBig(x *big.Int, fixedLen int) (*secret.SignedInt, error) {
	if x == nil || fixedLen <= 0 {
		return nil, errors.New("invalid signed secret integer")
	}
	magnitude := new(big.Int).Abs(x)
	defer secret.ClearBigInt(magnitude)
	if magnitude.BitLen() > fixedLen*8 {
		return nil, errors.New("signed secret integer exceeds fixed width")
	}
	encoded, err := paillierct.FixedEncodeStrict(magnitude, fixedLen)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return secret.NewSignedInt(x.Sign() < 0, encoded, fixedLen)
}

func signedSecretFromScalar(x *secret.Scalar, fixedLen int) (*secret.SignedInt, error) {
	value, err := secretScalarBig(x)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(value)
	return signedSecretFromBig(value, fixedLen)
}

func signedSecretBig(x *secret.SignedInt) (*big.Int, error) {
	if x == nil || x.FixedLen() == 0 {
		return nil, errors.New("invalid signed secret integer")
	}
	magnitude := x.FixedMagnitude()
	defer clear(magnitude)
	out := new(big.Int).SetBytes(magnitude)
	sign, err := x.SelectBySign([]byte{0}, []byte{1})
	if err != nil {
		secret.ClearBigInt(out)
		return nil, err
	}
	defer clear(sign)
	if sign[0] == 1 {
		out.Neg(out)
	}
	return out, nil
}

func sampleSignedSecret(rng io.Reader, bits uint32) (*secret.SignedInt, error) {
	value, err := SampleSignedPowerOfTwo(rng, bits)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(value)
	return signedSecretFromBig(value, signedPowerOfTwoBytes(bits))
}

func sampleMultRangeSecret(rng io.Reader, bits uint32, n *big.Int) (*secret.SignedInt, error) {
	value, err := SampleMultRange(rng, bits, n)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(value)
	return signedSecretFromBig(value, multRangeBytes(n, bits))
}

func sampleZNStarSecret(rng io.Reader, n *big.Int) (*secret.Scalar, error) {
	value, err := SampleZNStar(rng, n)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(value)
	return secretScalarFromBig(value, modulusBytes(n))
}
