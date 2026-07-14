package ed25519

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

const signingNonceContextLabel = "frost-ed25519-signing-nonce-context-v1"

func signingNonceGenerate(
	secret *fed.Scalar,
	reader io.Reader,
	sessionID tss.SessionID,
	message, contextHash, planHash []byte,
	purpose string,
) (*fed.Scalar, error) {
	binding := transcript.New(signingNonceContextLabel)
	binding.AppendBytes("session_id", sessionID[:])
	binding.AppendString("purpose", purpose)
	binding.AppendBytes("message", message)
	binding.AppendBytes("context_hash", contextHash)
	binding.AppendBytes("plan_hash", planHash)
	bindingHash := binding.Sum()
	defer clear(bindingHash)
	return signingNonceGenerateWithBinding(secret, reader, bindingHash)
}

// rfc9591NonceGenerate implements the exact RFC 9591 nonce_generate input. It
// is kept separate from the repository-bound production derivation so
// conformance vectors cannot silently select a different algorithm by reader
// dynamic type.
func rfc9591NonceGenerate(secret *fed.Scalar, reader io.Reader) (*fed.Scalar, error) {
	return signingNonceGenerateWithBinding(secret, reader, nil)
}

func signingNonceGenerateWithBinding(secret *fed.Scalar, reader io.Reader, binding []byte) (*fed.Scalar, error) {
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
	if len(binding) > 0 {
		h.Write(binding)
	}

	uniform := h.Sum(nil)
	defer clear(uniform)
	nonce, err := fed.NewScalar().SetUniformBytes(uniform)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}
