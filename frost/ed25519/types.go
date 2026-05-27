package ed25519

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
	
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

const protocol = "frost-ed25519"

const (
	payloadKeygenCommitments = "frost.ed25519.keygen.commitments"
	payloadKeygenShare       = "frost.ed25519.keygen.share"
	payloadSignCommitment    = "frost.ed25519.sign.commitment"
	payloadSignPartial       = "frost.ed25519.sign.partial"
)

// VerificationShare is a participant public share derived from DKG commitments.
type VerificationShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
}

// KeyShare is one local FROST Ed25519 signing share.
type KeyShare struct {
	Version            uint16        `json:"version"`
	Party              tss.PartyID   `json:"party"`
	Threshold          int           `json:"threshold"`
	Parties            []tss.PartyID `json:"parties"`
	PublicKey          []byte        `json:"public_key"`
	Secret             []byte
	GroupCommitments   [][]byte            `json:"group_commitments"`
	VerificationShares []VerificationShare `json:"verification_shares"`
}

// Algorithm returns the common algorithm identifier.
func (k *KeyShare) Algorithm() tss.Algorithm {
	return tss.AlgorithmFROSTEd25519
}

// PartyID returns the owner party of this key share.
func (k *KeyShare) PartyID() tss.PartyID {
	if k == nil {
		return 0
	}
	return k.Party
}

// PublicKeyBytes returns a copy of the group Ed25519 public key.
func (k *KeyShare) PublicKeyBytes() []byte {
	if k == nil {
		return nil
	}
	return slices.Clone(k.PublicKey)
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return marshalKeyShare(k)
}

// MarshalJSON rejects default JSON encoding of secret-bearing key shares.
func (k KeyShare) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 key share contains secret material; use MarshalBinary")
}

// UnmarshalKeyShare decodes a canonical FROST key-share record.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	return unmarshalKeyShare(in)
}

// Validate checks share structure and canonical scalar/point encodings.
func (k *KeyShare) Validate() error {
	if k == nil {
		return errors.New("nil key share")
	}
	if k.Version != tss.Version {
		return fmt.Errorf("unexpected key share version %d", k.Version)
	}
	if k.Threshold <= 0 || k.Threshold > len(k.Parties) {
		return errors.New("invalid threshold")
	}
	if err := wire.ValidateStrictSortedIDs(k.Parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.Parties, k.Party) {
		return errors.New("key share party is not in participant set")
	}
	if _, err := edcurve.PointFromBytes(k.PublicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if _, err := edcurve.ScalarFromCanonical(k.Secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.GroupCommitments) != k.Threshold {
		return errors.New("group commitments length must equal threshold")
	}
	for i, commitment := range k.GroupCommitments {
		if i == 0 {
			if _, err := edcurve.PointFromBytes(commitment); err != nil {
				return fmt.Errorf("invalid group commitment %d: %w", i, err)
			}
			continue
		}
		if _, err := edcurve.PointFromBytesAllowIdentity(commitment); err != nil {
			return fmt.Errorf("invalid group commitment %d: %w", i, err)
		}
	}
	if len(k.VerificationShares) != len(k.Parties) {
		return errors.New("verification share count must equal party count")
	}
	seen := make(map[tss.PartyID]struct{}, len(k.VerificationShares))
	for i, vs := range k.VerificationShares {
		if vs.Party != k.Parties[i] {
			return errors.New("verification shares must follow party order")
		}
		if !tss.ContainsParty(k.Parties, vs.Party) {
			return fmt.Errorf("verification share for non-participant %d", vs.Party)
		}
		if _, ok := seen[vs.Party]; ok {
			return fmt.Errorf("duplicate verification share for %d", vs.Party)
		}
		seen[vs.Party] = struct{}{}
		if _, err := edcurve.PointFromBytesAllowIdentity(vs.PublicKey); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", vs.Party, err)
		}
	}
	return nil
}

// Destroy zeros the local scalar share bytes in place.
func (k *KeyShare) Destroy() {
	if k == nil {
		return
	}
	clear(k.Secret)
}

func (k *KeyShare) secretBig() (*big.Int, error) {
	s, err := edcurve.ScalarFromCanonical(k.Secret)
	if err != nil {
		return nil, err
	}
	return edcurve.ScalarToBig(s), nil
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	for _, vs := range k.VerificationShares {
		if vs.Party == id {
			return vs.PublicKey, true
		}
	}
	return nil, false
}

func scalarBytes(x *big.Int) ([]byte, error) {
	s, err := edcurve.ScalarFromBig(x)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}
