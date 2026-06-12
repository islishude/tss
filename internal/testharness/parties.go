package testharness

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// Parties returns a sorted party set {1, 2, ..., n}.
func Parties(n int) []tss.PartyID {
	return testutil.MustPartySet(n)
}

// ThresholdCase bundles threshold and party count for table-driven tests.
type ThresholdCase struct {
	Threshold int
	Parties   int
}

// N returns the total number of parties.
func (tc ThresholdCase) N() int { return tc.Parties }

// T returns the threshold.
func (tc ThresholdCase) T() int { return tc.Threshold }

// SignerSubset returns the parties at the given 1-based indices.
func SignerSubset(all []tss.PartyID, ids ...int) []tss.PartyID {
	out := make([]tss.PartyID, len(ids))
	for i, id := range ids {
		out[i] = all[id-1]
	}
	return out
}
