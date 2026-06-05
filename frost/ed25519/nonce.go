package ed25519

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	fed "filippo.io/edwards25519"
)

func signingNonceGenerate(secret *fed.Scalar, reader io.Reader) ([]byte, error) {
	if secret == nil {
		return nil, errors.New("nil signing secret")
	}
	if reader == nil {
		reader = cryptorand.Reader
	}

	var randomBytes [32]byte
	if _, err := io.ReadFull(reader, randomBytes[:]); err != nil {
		return nil, err
	}
	defer clear(randomBytes[:])

	secretEnc := secret.Bytes()
	defer clear(secretEnc)

	h := sha512.New()
	h.Write([]byte(rfc9591ContextString))
	h.Write([]byte("nonce"))
	h.Write(randomBytes[:])
	h.Write(secretEnc)

	nonce, err := fed.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return nonce.Bytes(), nil
}
