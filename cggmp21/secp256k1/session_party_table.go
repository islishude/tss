package secp256k1

import "github.com/islishude/tss"

type partyTable[T any] struct {
	order tss.PartySet
	index map[tss.PartyID]int
	rows  []T
}

func newPartyTable[T any](parties tss.PartySet, init func(tss.PartyID) T) partyTable[T] {
	order := parties.Sorted()
	table := partyTable[T]{
		order: order,
		index: make(map[tss.PartyID]int, len(order)),
		rows:  make([]T, len(order)),
	}
	for i, id := range order {
		table.index[id] = i
		if init != nil {
			table.rows[i] = init(id)
		}
	}
	return table
}

func (t *partyTable[T]) Get(id tss.PartyID) (*T, bool) {
	if t == nil || t.index == nil {
		return nil, false
	}
	i, ok := t.index[id]
	if !ok {
		return nil, false
	}
	return &t.rows[i], true
}

func (t *partyTable[T]) MustGet(id tss.PartyID) *T {
	row, ok := t.Get(id)
	if !ok {
		panic("party table missing party")
	}
	return row
}

func (t *partyTable[T]) ForEach(fn func(id tss.PartyID, row *T) error) error {
	if t == nil || fn == nil {
		return nil
	}
	for i, id := range t.order {
		if err := fn(id, &t.rows[i]); err != nil {
			return err
		}
	}
	return nil
}

func (t *partyTable[T]) Count(fn func(row T) bool) int {
	if t == nil || fn == nil {
		return 0
	}
	count := 0
	for _, row := range t.rows {
		if fn(row) {
			count++
		}
	}
	return count
}

func (t *partyTable[T]) All(fn func(row T) bool) bool {
	if t == nil || fn == nil {
		return false
	}
	for _, row := range t.rows {
		if !fn(row) {
			return false
		}
	}
	return true
}

func (t *partyTable[T]) IDsWhere(fn func(row T) bool) []tss.PartyID {
	if t == nil || fn == nil {
		return nil
	}
	out := make(tss.PartySet, 0)
	for i, row := range t.rows {
		if fn(row) {
			out = append(out, t.order[i])
		}
	}
	return out
}
