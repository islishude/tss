package tss

import (
	"bytes"
	"slices"
	"testing"
)

func TestPartySetHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		hashA     func() []byte
		hashB     func() []byte
		wantEqual bool
	}{
		{
			name: "same set different order produces same hash",
			hashA: func() []byte {
				return PartySetHash(NewPartySet(1, 2, 3), "test-v1")
			},
			hashB: func() []byte {
				return PartySetHash(NewPartySet(3, 1, 2), "test-v1")
			},
			wantEqual: true,
		},
		{
			name: "different sets produce different hashes",
			hashA: func() []byte {
				return PartySetHash(NewPartySet(1, 2), "test-v1")
			},
			hashB: func() []byte {
				return PartySetHash(NewPartySet(1, 2, 3), "test-v1")
			},
			wantEqual: false,
		},
		{
			name: "different labels produce different hashes",
			hashA: func() []byte {
				return PartySetHash(NewPartySet(1, 2), "keygen-v1")
			},
			hashB: func() []byte {
				return PartySetHash(NewPartySet(1, 2), "signing-v1")
			},
			wantEqual: false,
		},
		{
			name: "deterministic",
			hashA: func() []byte {
				parties := NewPartySet(5, 1, 9)
				return PartySetHash(parties, "test-v1")
			},
			hashB: func() []byte {
				parties := NewPartySet(5, 1, 9)
				return PartySetHash(parties, "test-v1")
			},
			wantEqual: true,
		},
		{
			name: "deterministic with same party set instance",
			hashA: func() []byte {
				parties := NewPartySet(5, 1, 9)
				return PartySetHash(parties, "test-v1")
			},
			hashB: func() []byte {
				parties := NewPartySet(5, 1, 9)
				return PartySetHash(parties, "test-v1")
			},
			wantEqual: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotEqual := bytes.Equal(tc.hashA(), tc.hashB())
			if gotEqual != tc.wantEqual {
				t.Fatalf("bytes.Equal(...) = %v, want %v", gotEqual, tc.wantEqual)
			}
		})
	}
}

func TestPartySetHash_Length(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		parties PartySet
		label   string
		wantLen int
	}{
		{
			name:    "empty slice",
			parties: nil,
			label:   "test-v1",
			wantLen: 32,
		},
		{
			name:    "single party",
			parties: NewPartySet(42),
			label:   "test-v1",
			wantLen: 32,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := PartySetHash(tc.parties, tc.label)
			if len(h) != tc.wantLen {
				t.Fatalf("len(PartySetHash(...)) = %d, want %d", len(h), tc.wantLen)
			}
		})
	}
}

func TestMergePartySet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sets []PartySet
		want PartySet
	}{
		{
			name: "no sets",
			sets: nil,
			want: nil,
		},
		{
			name: "nil set",
			sets: []PartySet{nil},
			want: nil,
		},
		{
			name: "empty set",
			sets: []PartySet{{}},
			want: nil,
		},
		{
			name: "single set sorted",
			sets: []PartySet{{1, 2, 3}},
			want: PartySet{1, 2, 3},
		},
		{
			name: "single set unsorted is sorted",
			sets: []PartySet{{3, 1, 2}},
			want: PartySet{1, 2, 3},
		},
		{
			name: "single set duplicates are removed",
			sets: []PartySet{{3, 1, 2, 3, 1}},
			want: PartySet{1, 2, 3},
		},
		{
			name: "multiple sets are merged and sorted",
			sets: []PartySet{
				{3, 1},
				{2, 5},
				{4},
			},
			want: PartySet{1, 2, 3, 4, 5},
		},
		{
			name: "duplicates across sets are removed",
			sets: []PartySet{
				{1, 2, 3},
				{3, 4},
				{2, 5, 1},
			},
			want: PartySet{1, 2, 3, 4, 5},
		},
		{
			name: "nil and empty sets are ignored",
			sets: []PartySet{
				nil,
				{},
				{2, 1},
				nil,
			},
			want: PartySet{1, 2},
		},
		{
			name: "zero and max party id",
			sets: []PartySet{
				{^PartyID(0), 0},
				{1, ^PartyID(0)},
			},
			want: PartySet{0, 1, ^PartyID(0)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := MergePartySet(tc.sets...)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("MergePartySet(...) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMergePartySet_DoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	a := PartySet{3, 1, 2, 1}
	b := PartySet{5, 4, 3}

	origA := slices.Clone(a)
	origB := slices.Clone(b)

	got := MergePartySet(a, b)
	if !slices.Equal(got, PartySet{1, 2, 3, 4, 5}) {
		t.Fatalf("MergePartySet(...) = %v, want %v", got, PartySet{1, 2, 3, 4, 5})
	}

	if !slices.Equal(a, origA) {
		t.Fatalf("first input mutated: got %v, want %v", a, origA)
	}
	if !slices.Equal(b, origB) {
		t.Fatalf("second input mutated: got %v, want %v", b, origB)
	}
}
