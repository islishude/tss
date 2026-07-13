package paillier

import (
	"fmt"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	transcriptpkg "github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkchallenge "github.com/islishude/tss/internal/zk/challenge"
)

const (
	paillierChallengeDerivationLabel = "github.com/islishude/tss/internal/zk/paillier/challenge/v1"
	challengeCounterLimit            = 256
)

// Transcript is a Fiat-Shamir transcript that accumulates labeled protocol
// messages and derives a canonical positive challenge. Every field is
// length-prefixed and labeled for domain separation.
type Transcript struct {
	builder *transcriptpkg.Builder
}

// NewTranscript creates a transcript with the given domain separation label.
func NewTranscript(domain string) *Transcript {
	return &Transcript{builder: transcriptpkg.New(domain)}
}

// AppendBytes writes a labeled byte string into the transcript.
func (t *Transcript) AppendBytes(label string, b []byte) {
	t.builder.AppendBytes(label, b)
}

// AppendBigInt writes a labeled positive big.Int in canonical big-endian form.
func (t *Transcript) AppendBigInt(label string, x *big.Int) error {
	if x == nil {
		return fmt.Errorf("transcript AppendBigInt %s: nil integer", label)
	}
	b := x.Bytes() // canonical big-endian, no leading zero
	t.AppendBytes(label, b)
	return nil
}

// AppendSigned writes a labeled signed integer in canonical signed-magnitude form.
func (t *Transcript) AppendSigned(label string, x *big.Int) error {
	if x == nil {
		return fmt.Errorf("transcript AppendSigned %s: nil integer", label)
	}
	b, err := wire.EncodeBigInt(x)
	if err != nil {
		return fmt.Errorf("transcript AppendSigned %s: %w", label, err)
	}
	t.AppendBytes(label, b)
	return nil
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
	t.builder.AppendUint32(label, v)
}

// AppendUint16 writes a labeled uint16 in big-endian encoding.
func (t *Transcript) AppendUint16(label string, v uint16) {
	t.builder.AppendUint16(label, v)
}

// ChallengeSigned derives a non-zero Fiat-Shamir integer challenge. Production
// 256-bit profiles rejection-sample a canonical non-zero secp256k1 scalar and
// return its positive integer representative. Explicit reduced test profiles
// sample uniformly from [1, 2^bits).
func (t *Transcript) ChallengeSigned(bits uint32) (*big.Int, error) {
	_, value, err := t.ChallengeScalar(bits)
	return value, err
}

// ChallengeScalar derives the same challenge as ChallengeSigned and also
// returns its exact secp256k1 scalar representative. Production profiles use
// canonical non-zero rejection sampling; explicit reduced test profiles retain
// their smaller challenge space without modular reduction.
func (t *Transcript) ChallengeScalar(bits uint32) (secp.Scalar, *big.Int, error) {
	if bits == 0 || bits > 256 {
		return secp.Scalar{}, nil, fmt.Errorf("challenge bits must be in [1, 256], got %d", bits)
	}
	root := t.builder.Sum()
	if bits == 256 {
		challenge, err := zkchallenge.DeriveCanonicalNonZeroSecp256k1(
			paillierChallengeDerivationLabel,
			root,
			challengeCounterLimit,
		)
		if err != nil {
			return secp.Scalar{}, nil, err
		}
		encoded := challenge.Bytes()
		return challenge, new(big.Int).SetBytes(encoded), nil
	}
	value, err := zkchallenge.DeriveNonZeroBits(
		paillierChallengeDerivationLabel,
		root,
		bits,
		challengeCounterLimit,
	)
	if err != nil {
		return secp.Scalar{}, nil, err
	}
	return secp.ScalarFromBigInt(value), value, nil
}

// Sum returns the current transcript hash without modifying state.
func (t *Transcript) Sum() []byte {
	return t.builder.Sum()
}

func appendSecurityParams(t *Transcript, params SecurityParams) {
	t.AppendUint32("ell", params.Ell)
	t.AppendUint32("ell_prime", params.EllPrime)
	t.AppendUint32("epsilon", params.Epsilon)
	t.AppendUint32("challenge_bits", params.ChallengeBits)
	t.AppendUint32("min_paillier_bits", params.MinPaillierBits)
}
