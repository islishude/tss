package tss

import (
	"errors"
	"fmt"

	"github.com/islishude/tss/internal/transcript"
)

const envelopeSigningDigestLabel = "github.com/islishude/tss/envelope-signature/v1"

// EnvelopeSigner signs a canonical envelope digest with the local party's
// transport identity key.
type EnvelopeSigner interface {
	SignEnvelopeDigest(digest [32]byte) ([]byte, error)
}

// EnvelopeSignatureVerifier verifies a canonical envelope signature for party.
type EnvelopeSignatureVerifier interface {
	VerifyEnvelopeSignature(party PartyID, digest [32]byte, signature []byte) error
}

// EnvelopeSigningDigest computes the digest authenticated by SenderSignature.
// The signature field itself is deliberately excluded.
func EnvelopeSigningDigest(e Envelope) [32]byte {
	t := transcript.New(envelopeSigningDigestLabel)
	t.AppendString("protocol", string(e.Protocol))
	t.AppendUint16("version", ProtocolVersion)
	t.AppendBytes("session_id", e.SessionID[:])
	t.AppendUint8("round", e.Round)
	t.AppendUint32("from", e.From)
	t.AppendUint32("to", e.To)
	t.AppendString("payload_type", string(e.PayloadType))
	t.AppendBytes("payload", e.Payload)
	return t.Sum32()
}

// SignEnvelope returns an independently owned envelope carrying a portable
// sender signature.
func SignEnvelope(e Envelope, signer EnvelopeSigner) (Envelope, error) {
	if signer == nil {
		return Envelope{}, errors.New("nil EnvelopeSigner")
	}
	signature, err := signer.SignEnvelopeDigest(EnvelopeSigningDigest(e))
	if err != nil {
		return Envelope{}, fmt.Errorf("sign envelope for party %d: %w", e.From, err)
	}
	if len(signature) == 0 {
		return Envelope{}, errors.New("empty envelope signature")
	}
	if len(signature) > DefaultMaxEnvelopeSignatureBytes {
		return Envelope{}, fmt.Errorf("envelope sender signature too large: %d > %d", len(signature), DefaultMaxEnvelopeSignatureBytes)
	}
	clone := e.Clone()
	clone.SenderSignature = signature
	return clone, nil
}

// VerifyEnvelopeSignature verifies the portable sender signature carried by e.
func VerifyEnvelopeSignature(e Envelope, verifier EnvelopeSignatureVerifier) error {
	if verifier == nil {
		return ErrMissingEnvelopeSignatureVerifier
	}
	if len(e.SenderSignature) == 0 {
		return ErrMissingEnvelopeSignature
	}
	if err := verifier.VerifyEnvelopeSignature(e.From, EnvelopeSigningDigest(e), e.SenderSignature); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEnvelopeSignature, err)
	}
	return nil
}
