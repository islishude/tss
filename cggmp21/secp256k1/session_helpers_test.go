package secp256k1

import (
	"reflect"
	"testing"

	"github.com/islishude/tss"
)

func TestSessionSlotValidInvalid(t *testing.T) {
	t.Parallel()

	empty := emptySlot[int]()
	if empty.Valid() {
		t.Fatal("empty slot reported valid")
	}
	if value, ok := empty.Value(); ok || value != 0 {
		t.Fatalf("empty slot value = (%d, %v), want zero false", value, ok)
	}

	filled := someSlot("ready")
	if !filled.Valid() {
		t.Fatal("filled slot reported invalid")
	}
	if value, ok := filled.Value(); !ok || value != "ready" {
		t.Fatalf("filled slot value = (%q, %v), want ready true", value, ok)
	}
}

func TestSessionPartyTableDeterministicLookupAndPredicates(t *testing.T) {
	t.Parallel()

	table := newPartyTable(tss.NewPartySet(3, 1, 2), func(id tss.PartyID) int {
		return int(id) * 10
	})
	var ids []tss.PartyID
	if err := table.ForEach(func(id tss.PartyID, row *int) error {
		ids = append(ids, id)
		*row = *row + 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []tss.PartyID{1, 2, 3}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("iteration order = %v, want %v", ids, want)
	}
	row, ok := table.Get(2)
	if !ok || *row != 21 {
		t.Fatalf("party 2 row = (%v, %v), want 21 true", row, ok)
	}
	if row := table.MustGet(1); *row != 11 {
		t.Fatalf("MustGet(1) = %d, want 11", *row)
	}
	if _, ok := table.Get(99); ok {
		t.Fatal("missing party lookup succeeded")
	}
	if count := table.Count(func(row int) bool { return row > 15 }); count != 2 {
		t.Fatalf("Count(row > 15) = %d, want 2", count)
	}
	if !table.All(func(row int) bool { return row > 0 }) {
		t.Fatal("All(row > 0) returned false")
	}
	got := table.IDsWhere(func(row int) bool { return row%2 == 1 })
	if want := []tss.PartyID{1, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IDsWhere(odd row) = %v, want %v", got, want)
	}
}

func TestSessionCleanupStackLIFOAndDisarm(t *testing.T) {
	t.Parallel()

	var calls []int
	cleanup := newCleanupStack()
	cleanup.Add(func() { calls = append(calls, 1) })
	cleanup.Add(func() { calls = append(calls, 2) })
	cleanup.Run()
	cleanup.Run()
	if want := []int{2, 1}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup calls = %v, want %v", calls, want)
	}

	disarmed := newCleanupStack()
	disarmed.Add(func() { calls = append(calls, 3) })
	disarmed.Disarm()
	disarmed.Run()
	if want := []int{2, 1}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("disarmed cleanup calls = %v, want %v", calls, want)
	}
}

func TestSessionTransitionShape(t *testing.T) {
	t.Parallel()

	concrete := &helperTransition{}
	var transition sessionTransition[helperTransitionState] = concrete
	state := helperTransitionState{}
	effects, err := transition.Apply(&state)
	if err != nil {
		t.Fatal(err)
	}
	if len(effects.envelopes) != 0 {
		t.Fatalf("effects contained %d envelopes", len(effects.envelopes))
	}
	transition.CleanupOnReject()
	if !concrete.cleaned {
		t.Fatal("transition cleanup was not recorded")
	}
	transition.MarkCommitted()
	if !state.applied {
		t.Fatal("transition did not apply")
	}
	if !concrete.committed {
		t.Fatal("transition commit was not recorded")
	}
}

type helperTransitionState struct {
	applied bool
}

type helperTransition struct {
	committed bool
	cleaned   bool
}

func (t *helperTransition) Apply(state *helperTransitionState) (sessionEffects, error) {
	state.applied = true
	return sessionEffects{}, nil
}

func (t *helperTransition) CleanupOnReject() {
	if !t.committed {
		t.cleaned = true
	}
}

func (t *helperTransition) MarkCommitted() {
	t.committed = true
}
