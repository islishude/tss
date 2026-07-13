// Package challenge derives canonical Fiat-Shamir challenges from transcript
// roots. It does not construct proof transcripts; callers remain responsible
// for binding every statement and commitment before passing the resulting
// SHA-256 root here.
package challenge

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
)

const maxCounterLimit uint32 = 256

// ErrRejectionLimit reports that every explicitly permitted challenge
// candidate was rejected.
var ErrRejectionLimit = errors.New("challenge: rejection counter limit exhausted")

// DeriveCanonicalNonZeroSecp256k1 derives a uniformly distributed non-zero
// secp256k1 scalar by rejection sampling SHA-256 transcript roots. root is the
// already domain-separated proof transcript hash. domainLabel separates retry
// hashes from every other repository transcript, and counterLimit explicitly
// bounds the total number of labeled expansion candidates. Counter zero is
// also expanded as H(domainLabel, root, 0); the raw root is never interpreted
// directly as a scalar.
//
// Candidate zero and every candidate greater than or equal to the subgroup
// order are rejected rather than reduced. This prevents both modular bias and
// challenges that are non-zero as integers but zero as effective scalars.
func DeriveCanonicalNonZeroSecp256k1(domainLabel string, root []byte, counterLimit uint32) (secp.Scalar, error) {
	if err := validateInputs(domainLabel, root, counterLimit); err != nil {
		return secp.Scalar{}, err
	}
	for counter := range counterLimit {
		candidate := challengeCandidate(domainLabel, root, counter)
		scalar, ok := canonicalNonZeroSecp256k1Candidate(candidate)
		clear(candidate)
		if ok {
			return scalar, nil
		}
	}
	return secp.Scalar{}, ErrRejectionLimit
}

// DeriveNonZeroBits derives a uniformly distributed non-zero integer in
// [1, 2^bits). It exists only for explicit reduced-parameter proof profiles;
// production secp256k1 proofs must use DeriveCanonicalNonZeroSecp256k1.
func DeriveNonZeroBits(domainLabel string, root []byte, bits, counterLimit uint32) (*big.Int, error) {
	if err := validateInputs(domainLabel, root, counterLimit); err != nil {
		return nil, err
	}
	if bits == 0 || bits > 256 {
		return nil, fmt.Errorf("challenge: bits must be in [1, 256], got %d", bits)
	}
	mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	mask.Sub(mask, big.NewInt(1))
	for counter := range counterLimit {
		candidate := challengeCandidate(domainLabel, root, counter)
		value := new(big.Int).SetBytes(candidate)
		clear(candidate)
		value.And(value, mask)
		if value.Sign() != 0 {
			return value, nil
		}
	}
	return nil, ErrRejectionLimit
}

func validateInputs(domainLabel string, root []byte, counterLimit uint32) error {
	if domainLabel == "" {
		return errors.New("challenge: empty derivation domain")
	}
	if len(root) != sha256.Size {
		return fmt.Errorf("challenge: transcript root must be %d bytes", sha256.Size)
	}
	if counterLimit == 0 || counterLimit > maxCounterLimit {
		return fmt.Errorf("challenge: counter limit must be in [1, %d]", maxCounterLimit)
	}
	return nil
}

func challengeCandidate(domainLabel string, root []byte, counter uint32) []byte {
	t := transcript.New(domainLabel)
	t.AppendBytes("root", root)
	t.AppendUint32("counter", counter)
	return t.Sum()
}

func canonicalNonZeroSecp256k1Candidate(candidate []byte) (secp.Scalar, bool) {
	scalar, err := secp.ScalarFromBytes(candidate)
	return scalar, err == nil
}
