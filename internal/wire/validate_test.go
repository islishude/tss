package wire

import "testing"

func TestValidateStrictSortedIDs(t *testing.T) {
	if err := ValidateStrictSortedIDs([]testID{1, 3, 5}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ids  []testID
	}{
		{name: "empty", ids: nil},
		{name: "zero", ids: []testID{0}},
		{name: "duplicate", ids: []testID{1, 1}},
		{name: "unsorted", ids: []testID{2, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateStrictSortedIDs(tc.ids); err == nil {
				t.Fatal("accepted invalid IDs")
			}
		})
	}
}
