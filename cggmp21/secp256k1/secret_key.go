package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
)

// SecretKey is an explicitly exportable canonical secp256k1 private key.
type SecretKey struct {
	state *secretKeyState
}

type secretKeyState struct {
	scalar *secret.Scalar
}

// ParseSecretKey parses a canonical 32-byte big-endian non-zero secp256k1
// private key.
func ParseSecretKey(encoded []byte) (*SecretKey, error) {
	scalar, err := secp.ScalarFromBytes(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 secret key: %w", err)
	}
	return newCGGMPSecretKey(scalar)
}

func newCGGMPSecretKey(scalar secp.Scalar) (*SecretKey, error) {
	value, err := secpSecretScalarFromScalar(scalar)
	if err != nil {
		return nil, err
	}
	return &SecretKey{state: &secretKeyState{scalar: value}}, nil
}

// MarshalBinary exports the canonical fixed-width 32-byte big-endian private
// key. The caller owns the returned secret bytes and must clear them.
func (k *SecretKey) MarshalBinary() ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	return k.state.scalar.FixedBytes(), nil
}

// MarshalJSON rejects JSON encoding of secret keys.
func (k SecretKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 secret key must not be JSON-encoded")
}

// PublicKey returns the canonical compressed secp256k1 public key.
func (k *SecretKey) PublicKey() ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	scalar, err := secpScalarFromSecret(k.state.scalar)
	if err != nil {
		return nil, err
	}
	return secp.PointBytes(secp.ScalarBaseMult(scalar))
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
	if _, err := secpScalarFromSecret(k.state.scalar); err != nil {
		return fmt.Errorf("invalid secp256k1 secret key: %w", err)
	}
	return nil
}

// ReconstructSecretKey reconstructs the secp256k1 private key from at least
// the threshold number of distinct, consistent key shares. Input shares remain
// owned by the caller and are not modified or destroyed.
func ReconstructSecretKey(shares ...*KeyShare) (*SecretKey, error) {
	return ReconstructSecretKeyWithLimits(DefaultLimits(), shares...)
}

// ReconstructSecretKeyWithLimits reconstructs a secp256k1 private key using
// explicit local validation limits and cryptographic profiles.
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
	byID := make(map[tss.PartyID]*KeyShare, len(shares))
	for _, share := range shares {
		if err := validateCGGMPReconstructionShare(reference, share, limits); err != nil {
			return nil, err
		}
		id := share.state.Party
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate key share for party %d", id)
		}
		seen[id] = struct{}{}
		byID[id] = share
		ids = append(ids, id)
	}
	ids = tss.SortParties(ids)
	acc := secp.ScalarZero()
	for _, id := range ids {
		lambda, err := shamir.LagrangeCoefficient(id, ids)
		if err != nil {
			return nil, err
		}
		local, err := secpScalarFromSecret(byID[id].state.Secret)
		if err != nil {
			return nil, err
		}
		acc = secp.ScalarAdd(acc, secp.ScalarMul(lambda, local))
	}
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(acc))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(publicKey, reference.state.PublicKey) {
		return nil, errors.New("reconstructed secret does not match group public key")
	}
	return newCGGMPSecretKey(acc)
}

func validateCGGMPReconstructionShare(reference, candidate *KeyShare, limits Limits) error {
	if candidate == nil || candidate.state == nil {
		return errors.New("nil key share")
	}
	if err := candidate.ValidateWithLimits(limits); err != nil {
		return fmt.Errorf("invalid key share for reconstruction: %w", err)
	}
	referenceCommitments, err := secp.CommitmentPointsBytes(reference.state.GroupCommitments)
	if err != nil {
		return err
	}
	candidateCommitments, err := secp.CommitmentPointsBytes(candidate.state.GroupCommitments)
	if err != nil {
		return err
	}
	if candidate.state.Threshold != reference.state.Threshold ||
		!slices.Equal(candidate.state.Parties, reference.state.Parties) ||
		!bytes.Equal(candidate.state.PublicKey, reference.state.PublicKey) ||
		!bytes.Equal(candidate.state.ChainCode, reference.state.ChainCode) ||
		!equalByteSlices(candidateCommitments, referenceCommitments) ||
		candidate.state.PaillierProofSessionID != reference.state.PaillierProofSessionID ||
		candidate.state.PaillierProofDomain != reference.state.PaillierProofDomain ||
		!bytes.Equal(candidate.state.ResharePlanHash, reference.state.ResharePlanHash) ||
		!bytes.Equal(candidate.state.KeygenTranscriptHash, reference.state.KeygenTranscriptHash) ||
		!bytes.Equal(candidate.state.PlanHash, reference.state.PlanHash) ||
		candidate.state.SecurityParams != reference.state.SecurityParams {
		return errors.New("key shares are not from the same lifecycle generation")
	}
	return nil
}

func equalByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !bytes.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}
