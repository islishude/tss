package ed25519

import (
	"errors"
	"fmt"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

const edScalarSize = 32

func newEdSecretScalar(data []byte) (*secret.Scalar, error) {
	if len(data) != edScalarSize {
		return nil, fmt.Errorf("ed25519 secret scalar must be %d bytes", edScalarSize)
	}
	if _, err := edcurve.ScalarFromCanonical(data); err != nil {
		return nil, err
	}
	return secret.NewScalar(data, edScalarSize)
}

func edSecretScalarBytes(s *secret.Scalar) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil secret scalar")
	}
	if s.FixedLen() != edScalarSize {
		return nil, fmt.Errorf("ed25519 secret scalar has length %d, want %d", s.FixedLen(), edScalarSize)
	}
	out := s.FixedBytes()
	if _, err := edcurve.ScalarFromCanonical(out); err != nil {
		return nil, err
	}
	return out, nil
}

func edScalarFromSecret(s *secret.Scalar) (*fed.Scalar, error) {
	out, err := edSecretScalarBytes(s)
	if err != nil {
		return nil, err
	}
	return edcurve.ScalarFromCanonical(out)
}

func cloneEdSecretScalar(s *secret.Scalar) *secret.Scalar {
	if s == nil {
		return nil
	}
	out, err := secret.NewScalar(s.FixedBytes(), s.FixedLen())
	if err != nil {
		return nil
	}
	return out
}
