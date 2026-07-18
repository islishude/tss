package ed25519

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

// SecretKey is an explicitly exportable FROST Ed25519 group secret scalar.
//
// It contains the canonical little-endian scalar, not an RFC 8032 seed. A
// SecretKey reconstructed from threshold shares cannot recover the seed from
// which an imported key might originally have been derived.
type SecretKey struct {
	state *secretKeyState
}

type secretKeyState struct {
	scalar *secret.Scalar
}

// NewSecretKeyFromSeed derives the Ed25519 group secret scalar from a standard
// 32-byte RFC 8032 seed.
func NewSecretKeyFromSeed(seed []byte) (*SecretKey, error) {
	if len(seed) != 32 {
		return nil, errors.New("ed25519 seed must be 32 bytes")
	}
	digest := sha512.Sum512(seed)
	defer clear(digest[:])
	scalar, err := fed.NewScalar().SetBytesWithClamping(digest[:32])
	if err != nil {
		return nil, fmt.Errorf("derive ed25519 secret scalar: %w", err)
	}
	defer scalar.Set(fed.NewScalar())
	return newFROSTSecretKey(scalar)
}

// ParseSecretScalar parses a canonical 32-byte little-endian Ed25519 group
// secret scalar. Zero is rejected.
func ParseSecretScalar(encoded []byte) (*SecretKey, error) {
	scalar, err := edcurve.ScalarFromCanonical(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse ed25519 secret scalar: %w", err)
	}
	defer scalar.Set(fed.NewScalar())
	return newFROSTSecretKey(scalar)
}

func newFROSTSecretKey(scalar *fed.Scalar) (*SecretKey, error) {
	if scalar == nil {
		return nil, errors.New("nil ed25519 secret scalar")
	}
	if scalar.Equal(edcurve.ScalarZero()) == 1 {
		return nil, errors.New("ed25519 secret scalar is zero")
	}
	value, err := newEdSecretScalarFromFed(scalar)
	if err != nil {
		return nil, err
	}
	return &SecretKey{state: &secretKeyState{scalar: value}}, nil
}

// MarshalBinary exports the canonical fixed-width 32-byte little-endian group
// secret scalar. The caller owns the returned secret bytes and must clear them.
func (k *SecretKey) MarshalBinary() ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	return k.state.scalar.FixedBytes(), nil
}

// MarshalJSON rejects JSON encoding of secret keys.
func (k SecretKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 secret key must not be JSON-encoded")
}

// PublicKey returns the group public key corresponding to the secret scalar.
func (k *SecretKey) PublicKey() (PublicKeyPoint, error) {
	if err := k.validate(); err != nil {
		return PublicKeyPoint{}, err
	}
	scalar, err := edScalarFromSecret(k.state.scalar)
	if err != nil {
		return PublicKeyPoint{}, err
	}
	defer scalar.Set(fed.NewScalar())
	return newPublicKeyPointFromPoint(fed.NewIdentityPoint().ScalarBaseMult(scalar))
}

// Destroy clears the package-owned secret scalar. It is safe to call repeatedly.
func (k *SecretKey) Destroy() {
	if k == nil || k.state == nil || k.state.scalar == nil {
		return
	}
	k.state.scalar.Destroy()
}

// String returns a redacted representation.
func (k SecretKey) String() string { return "SecretKey{Scalar:<redacted>}" }

// GoString returns a redacted representation.
func (k SecretKey) GoString() string { return k.String() }

// Format writes a redacted representation for every formatting verb.
func (k SecretKey) Format(state fmt.State, verb rune) {
	_, _ = fmt.Fprint(state, k.String())
}

func (k *SecretKey) validate() error {
	if k == nil || k.state == nil || k.state.scalar == nil {
		return errors.New("nil secret key")
	}
	scalar, err := edScalarFromSecret(k.state.scalar)
	if err != nil {
		return fmt.Errorf("invalid ed25519 secret scalar: %w", err)
	}
	defer scalar.Set(fed.NewScalar())
	if scalar.Equal(edcurve.ScalarZero()) == 1 {
		return errors.New("destroyed or zero secret key")
	}
	return nil
}

// ReconstructSecretKey reconstructs the FROST group secret from at least the
// threshold number of distinct, consistent key shares. Input shares remain
// owned by the caller and are not modified or destroyed.
func ReconstructSecretKey(shares ...*KeyShare) (*SecretKey, error) {
	return ReconstructSecretKeyWithLimits(DefaultLimits(), shares...)
}

// ReconstructSecretKeyWithLimits reconstructs the FROST group secret using
// explicit local validation limits.
func ReconstructSecretKeyWithLimits(limits Limits, shares ...*KeyShare) (*SecretKey, error) {
	if len(shares) == 0 {
		return nil, errors.New("no key shares supplied")
	}
	reference := shares[0]
	if reference == nil || reference.state == nil {
		return nil, errors.New("nil key share")
	}
	if len(shares) < reference.state.Threshold {
		return nil, fmt.Errorf("insufficient key shares: got %d, need %d", len(shares), reference.state.Threshold)
	}
	ids := make(tss.PartySet, 0, len(shares))
	seen := make(map[tss.PartyID]struct{}, len(shares))
	for _, share := range shares {
		if err := validateFROSTReconstructionShare(reference, share, limits); err != nil {
			return nil, err
		}
		id := share.state.Party
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate key share for party %d", id)
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	ids = tss.SortParties(ids)
	acc := fed.NewScalar()
	defer acc.Set(fed.NewScalar())
	for _, id := range ids {
		var share *KeyShare
		for _, candidate := range shares {
			if candidate.state.Party == id {
				share = candidate
				break
			}
		}
		lambda, err := lagrangeCoefficientScalar(id, ids)
		if err != nil {
			return nil, err
		}
		local, err := share.secretScalar()
		if err != nil {
			lambda.Set(fed.NewScalar())
			return nil, err
		}
		term := fed.NewScalar().Multiply(lambda, local)
		acc.Add(acc, term)
		lambda.Set(fed.NewScalar())
		local.Set(fed.NewScalar())
		term.Set(fed.NewScalar())
	}
	if !pointEqual(fed.NewIdentityPoint().ScalarBaseMult(acc), reference.state.PublicKey.Point()) {
		return nil, errors.New("reconstructed secret does not match group public key")
	}
	return newFROSTSecretKey(acc)
}

func validateFROSTReconstructionShare(reference, candidate *KeyShare, limits Limits) error {
	if candidate == nil || candidate.state == nil {
		return errors.New("nil key share")
	}
	if err := candidate.ValidateWithLimits(limits); err != nil {
		return fmt.Errorf("invalid key share for reconstruction: %w", err)
	}
	if candidate.state.Threshold != reference.state.Threshold ||
		!slices.Equal(candidate.state.Parties, reference.state.Parties) ||
		!candidate.state.PublicKey.Equal(reference.state.PublicKey) ||
		!bytes.Equal(candidate.state.ChainCode, reference.state.ChainCode) ||
		!candidate.state.GroupCommitments.Equal(reference.state.GroupCommitments) ||
		candidate.state.KeygenSessionID != reference.state.KeygenSessionID ||
		!bytes.Equal(candidate.state.KeygenTranscriptHash, reference.state.KeygenTranscriptHash) ||
		!bytes.Equal(candidate.state.PlanHash, reference.state.PlanHash) ||
		candidate.state.ConfirmationMode != reference.state.ConfirmationMode {
		return errors.New("key shares are not from the same lifecycle generation")
	}
	return nil
}
