package ed25519

import (
	"errors"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

/*
Note:
secret.Scalar is used here as a fixed-size redacted byte container;
the bytes remain Ed25519 canonical scalar encoding.
*/

func newEdSecretScalar(data []byte) (*secret.Scalar, error) {
	scalar, err := edcurve.ScalarFromCanonical(data)
	if err != nil {
		return nil, err
	}
	scalar.Set(fed.NewScalar())
	return secret.NewScalar(data, edcurve.ScalarSize)
}

func newEdSecretScalarFromFed(s *fed.Scalar) (*secret.Scalar, error) {
	if s == nil {
		return nil, errors.New("nil secret scalar")
	}
	encoded := s.Bytes()
	defer clear(encoded)
	return newEdSecretScalar(encoded)
}

func edScalarFromSecret(s *secret.Scalar) (*fed.Scalar, error) {
	if s == nil {
		return nil, errors.New("nil secret scalar")
	}
	encoded := s.FixedBytes()
	defer clear(encoded)
	return edcurve.ScalarFromCanonical(encoded)
}

func validateEdSecretScalar(s *secret.Scalar) error {
	scalar, err := edScalarFromSecret(s)
	if scalar != nil {
		scalar.Set(fed.NewScalar())
	}
	return err
}
