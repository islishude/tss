package testutil

import "github.com/islishude/tss"

// SortedPartyMapKeys returns the party identifiers in m in ascending order.
// It returns nil when m is empty so snapshot zero values remain comparable.
func SortedPartyMapKeys[V any](m map[tss.PartyID]V) tss.PartySet {
	if len(m) == 0 {
		return nil
	}
	parties := make(tss.PartySet, 0, len(m))
	for party := range m {
		parties = append(parties, party)
	}
	return parties.Sorted()
}
