package tss

import (
	"errors"
	"fmt"
	"slices"
)

// PartySet is an ordered set of protocol participants.
type PartySet []PartyID

// Contains reports whether ps contains id
func (ps PartySet) Contains(id PartyID) bool {
	return ContainsParty(ps, id)
}

// Sorted returns a sorted copy of PartySet.
func (ps PartySet) Sorted() PartySet {
	return SortParties(ps)
}

// Clone returns a copy of PartySet with a separate backing array
func (ps PartySet) Clone() PartySet {
	return slices.Clone(ps)
}

// Add returns a new PartySet with given PartyID list
func (ps PartySet) Add(ids ...PartyID) PartySet {
	return append(ps, ids...)
}

// NewPartySet returns a PartySet containing parties in the given order.
func NewPartySet(parties ...PartyID) PartySet {
	return parties
}

// MergePartySet takes a set slice and returns a new sorted set containing elements which are in either or both of this set and the given set
func MergePartySet(sets ...PartySet) PartySet {
	var merged PartySet
	seen := make(map[PartyID]struct{})
	for _, set := range sets {
		for _, id := range set {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			merged = append(merged, id)
		}
	}
	slices.Sort(merged)
	return merged
}

// ContainsParty reports whether id appears in parties.
func ContainsParty(parties PartySet, id PartyID) bool {
	return slices.Contains(parties, id)
}

// SortParties returns a sorted copy of parties.
func SortParties(parties PartySet) PartySet {
	out := slices.Clone(parties)
	slices.Sort(out)
	return out
}

// ValidateSignerSet checks signers against a key's participant set and limits.
// It verifies: non-empty, minimum size (threshold), maximum size, membership,
// and no duplicates. For algorithms where AllowOversizedSignerSet is false,
// signer count must exactly equal threshold.
func ValidateSignerSet(keyParties PartySet, threshold int, signers PartySet, limits ThresholdLimits) error {
	if len(signers) == 0 {
		return errors.New("signers must not be empty")
	}
	if len(signers) < threshold {
		return fmt.Errorf("not enough signers: %d < threshold %d", len(signers), threshold)
	}
	if len(signers) > limits.MaxSigners {
		return fmt.Errorf("too many signers: %d > %d", len(signers), limits.MaxSigners)
	}
	if !limits.AllowOversizedSignerSet && len(signers) != threshold {
		return fmt.Errorf("signer count must equal threshold: got %d, want %d", len(signers), threshold)
	}
	seen := make(map[PartyID]struct{}, len(signers))
	for _, id := range signers {
		if !ContainsParty(keyParties, id) {
			return fmt.Errorf("signer %d is not a participant", id)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate signer %d", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
