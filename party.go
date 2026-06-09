package tss

import (
	"errors"
	"fmt"
	"slices"
)

// PartySet is an ordered set of protocol participants.
type PartySet []PartyID

// Contains reports whether id is in the party set.
func (ps PartySet) Contains(id PartyID) bool {
	return ContainsParty(ps, id)
}

// Sorted returns a sorted copy of the party set.
func (ps PartySet) Sorted() PartySet {
	return SortParties(ps)
}

// Clone returns a deep copy of the party set.
func (ps PartySet) Clone() PartySet {
	return slices.Clone(ps)
}

// ContainsParty reports whether id appears in parties.
func ContainsParty(parties []PartyID, id PartyID) bool {
	return slices.Contains(parties, id)
}

// SortParties returns a sorted copy of parties.
func SortParties(parties []PartyID) []PartyID {
	out := slices.Clone(parties)
	slices.Sort(out)
	return out
}

// ValidateSignerSet checks signers against a key's participant set and limits.
// It verifies: non-empty, minimum size (threshold), maximum size, membership,
// and no duplicates. For algorithms where AllowOversizedSignerSet is false,
// signer count must exactly equal threshold.
func ValidateSignerSet(keyParties []PartyID, threshold int, signers []PartyID, limits Limits) error {
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
