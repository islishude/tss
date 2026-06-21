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

type rfc9591NonceDerivationReader interface {
	io.Reader
	rfc9591NonceDerivation()
}

func signingNonceGenerate(
	secret *fed.Scalar,
	reader io.Reader,
	sessionID tss.SessionID,
	message, contextHash, planHash []byte,
	purpose string,
) (*fed.Scalar, error) {
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
	if _, vectorMode := reader.(rfc9591NonceDerivationReader); !vectorMode {
		binding := transcript.New(signingNonceContextLabel)
		binding.AppendBytes("session_id", sessionID[:])
		binding.AppendString("purpose", purpose)
		binding.AppendBytes("message", message)
		binding.AppendBytes("context_hash", contextHash)
		binding.AppendBytes("plan_hash", planHash)
		bindingHash := binding.Sum()
		h.Write(bindingHash)
		clear(bindingHash)
	}

	uniform := h.Sum(nil)
	defer clear(uniform)
	nonce, err := fed.NewScalar().SetUniformBytes(uniform)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}
