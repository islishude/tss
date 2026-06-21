package ed25519

type slot[T any] struct {
	v  T
	ok bool
}

func emptySlot[T any]() slot[T] {
	return slot[T]{}
}

func someSlot[T any](v T) slot[T] {
	return slot[T]{v: v, ok: true}
}

func (s slot[T]) Valid() bool {
	return s.ok
}

func (s slot[T]) Value() (T, bool) {
	return s.v, s.ok
}
