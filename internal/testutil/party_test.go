package testutil

import (
	"slices"
	"testing"

	"github.com/islishude/tss"
)

func TestSortedPartyMapKeys(t *testing.T) {
	t.Parallel()

	if got := SortedPartyMapKeys(map[tss.PartyID]string(nil)); got != nil {
		t.Fatalf("nil map keys = %v, want nil", got)
	}
	if got := SortedPartyMapKeys(map[tss.PartyID]string{}); got != nil {
		t.Fatalf("empty map keys = %v, want nil", got)
	}

	got := SortedPartyMapKeys(map[tss.PartyID]string{
		3: "three",
		1: "one",
		2: "two",
	})
	want := tss.PartySet{1, 2, 3}
	if !slices.Equal(got, want) {
		t.Fatalf("map keys = %v, want %v", got, want)
	}
}
