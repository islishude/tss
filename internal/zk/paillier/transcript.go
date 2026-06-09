package paillier

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

// Transcript is a Fiat-Shamir transcript that accumulates labeled protocol
// messages and derives a signed challenge. Every field is length-prefixed
// and labeled for domain separation.
type Transcript struct {
	domain string
	h      hash.Hash
}

// NewTranscript creates a transcript with the given domain separation label.
func NewTranscript(domain string) *Transcript {
	t := &Transcript{domain: domain}
	t.h = sha256.New()
	// Bind the domain label as the first transcript entry.
	t.AppendBytes("domain", []byte(domain))
	return t
}

// AppendBytes writes a labeled byte string into the transcript.
func (t *Transcript) AppendBytes(label string, b []byte) {
	wire.WriteHashPart(t.h, []byte(label))
	wire.WriteHashPart(t.h, b)
}

// AppendBigInt writes a labeled positive big.Int in canonical big-endian form.
func (t *Transcript) AppendBigInt(label string, x *big.Int) {
	b := x.Bytes() // canonical big-endian, no leading zero
	t.AppendBytes(label, b)
}

// AppendSigned writes a labeled signed integer in canonical signed-magnitude form.
func (t *Transcript) AppendSigned(label string, x *big.Int) {
	t.AppendBytes(label, EncodeSigned(x))
}

// AppendPoint writes a labeled secp256k1 curve point in compressed form.
// It returns an error if p is nil or not on the curve.
func (t *Transcript) AppendPoint(label string, p *secp.Point) error {
	b, err := secp.PointBytes(p)
	if err != nil {
		return fmt.Errorf("transcript AppendPoint %s: %w", label, err)
	}
	t.AppendBytes(label, b)
	return nil
}

// AppendPointBytes writes a labeled curve point from its compressed encoding.
// The encoding is validated before being added to the transcript.
func (t *Transcript) AppendPointBytes(label string, pointBytes []byte) error {
	if _, err := secp.PointFromBytes(pointBytes); err != nil {
		return fmt.Errorf("transcript AppendPointBytes %s: %w", label, err)
	}
	t.AppendBytes(label, pointBytes)
	return nil
}

// AppendUint32 writes a labeled uint32 in big-endian encoding.
func (t *Transcript) AppendUint32(label string, v uint32) {
	t.AppendBytes(label, wire.Uint32(v))
}

// AppendUint16 writes a labeled uint16 in big-endian encoding.
func (t *Transcript) AppendUint16(label string, v uint16) {
	t.AppendBytes(label, wire.Uint16(v))
}

// ChallengeSigned derives a Fiat-Shamir challenge as a signed integer in
// [0, 2^bits). The challenge is NOT reduced modulo a curve order — it is used
// as a full integer for Paillier-range proofs.
func (t *Transcript) ChallengeSigned(bits uint) (*big.Int, error) {
	if bits == 0 || bits > 256 {
		return nil, fmt.Errorf("challenge bits must be in [1, 256], got %d", bits)
	}
	digest := t.h.Sum(nil)
	challenge := new(big.Int).SetBytes(digest)
	// Reduce to the target bit length.
	mask := new(big.Int).Lsh(big.NewInt(1), bits)
	mask.Sub(mask, big.NewInt(1))
	challenge.And(challenge, mask)
	if challenge.Sign() == 0 {
		return nil, errors.New("transcript: zero challenge — re-run with fresh nonces")
	}
	return challenge, nil
}

// Sum returns the current transcript hash without modifying state.
func (t *Transcript) Sum() []byte {
	return t.h.Sum(nil)
}
