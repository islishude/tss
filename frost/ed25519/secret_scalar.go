package ed25519

import (
	"errors"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

func newEdSecretScalar(data []byte) (*secret.Scalar, error) {
	if _, err := edcurve.ScalarFromCanonical(data); err != nil {
		return nil, err
	}
	return secret.NewScalar(data, edcurve.ScalarSize)
}

func edSecretScalarBytes(s *secret.Scalar) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil secret scalar")
	}
	out := s.FixedBytes()
	if _, err := edcurve.ScalarFromCanonical(out); err != nil {
		return nil, err
	}
	return out, nil
}

func edScalarFromSecret(s *secret.Scalar) (*fed.Scalar, error) {
	if s == nil {
		return nil, errors.New("nil secret scalar")
	}
	return edcurve.ScalarFromCanonical(s.FixedBytes())
}
