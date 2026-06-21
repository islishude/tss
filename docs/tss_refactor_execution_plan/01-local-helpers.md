# Phase 01 — Package-Local Protocol Helpers

## Objective

Add small package-local helpers that make later refactors easier and safer. These helpers should not impose a cross-package framework yet.

## Scope

Add package-local helpers to both:

```text
frost/ed25519
cggmp21/secp256k1
```

Helpers:

1. `slot[T]` for optional typed state.
2. `partyTable[T]` for party-indexed state.
3. `cleanupStack` for staged resource cleanup.
4. Minimal transition/effects interfaces where useful.

## Non-goals

- Do not move helpers to `internal` yet.
- Do not rewrite handlers yet.
- Do not change public APIs.
- Do not change wire encoding.

## Files to add

Recommended:

```text
frost/ed25519/session_slot.go
frost/ed25519/session_party_table.go
frost/ed25519/session_cleanup.go
frost/ed25519/session_transition.go

cggmp21/secp256k1/session_slot.go
cggmp21/secp256k1/session_party_table.go
cggmp21/secp256k1/session_cleanup.go
cggmp21/secp256k1/session_transition.go
```

## Helper 1: `slot[T]`

Purpose: replace `haveX bool + x T` patterns with a single typed optional value.

Suggested implementation:

```go
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
```

Optional additions:

```go
func (s *slot[T]) Set(v T) bool
func (s *slot[T]) Clear()
func (s *slot[T]) Must() T
```

Keep the API small. Add methods only when a call site needs them.

## Helper 2: `partyTable[T]`

Purpose: centralize party lookup, sorted iteration, and derived readiness predicates.

Suggested implementation:

```go
type partyTable[T any] struct {
    order tss.PartySet
    index map[tss.PartyID]int
    rows  []T
}

func newPartyTable[T any](parties tss.PartySet, init func(tss.PartyID) T) partyTable[T]
func (t *partyTable[T]) Get(id tss.PartyID) (*T, bool)
func (t *partyTable[T]) MustGet(id tss.PartyID) *T
func (t *partyTable[T]) ForEach(fn func(id tss.PartyID, row *T) error) error
func (t *partyTable[T]) Count(fn func(row T) bool) int
func (t *partyTable[T]) All(fn func(row T) bool) bool
func (t *partyTable[T]) IDsWhere(fn func(row T) bool) []tss.PartyID
```

Rules:

- Iteration order must be deterministic.
- Do not expose mutable rows unless the caller is in commit code.
- Validation/build code should prefer read-only snapshots once introduced.

## Helper 3: `cleanupStack`

Purpose: guarantee that staged secret-bearing resources are destroyed unless ownership is committed.

Suggested implementation:

```go
type cleanupStack struct {
    fns   []func()
    armed bool
}

func newCleanupStack() *cleanupStack {
    return &cleanupStack{armed: true}
}

func (c *cleanupStack) Add(fn func()) {
    if fn != nil {
        c.fns = append(c.fns, fn)
    }
}

func (c *cleanupStack) Disarm() {
    c.armed = false
}

func (c *cleanupStack) Run() {
    if !c.armed {
        return
    }
    for i := len(c.fns) - 1; i >= 0; i-- {
        c.fns[i]()
    }
}
```

Usage pattern:

```go
cleanup := newCleanupStack()
defer cleanup.Run()

secretValue, err := makeSecret()
if err != nil {
    return nil, err
}
cleanup.Add(secretValue.Destroy)

prepared := &preparedThing{secret: secretValue}
cleanup.Disarm()
return prepared, nil
```

## Helper 4: transition/effects shape

Start with package-local interfaces. Do not overgeneralize.

Example for FROST signing:

```go
type signTransition interface {
    Apply(st *frostSignState) (signEffects, error)
    CleanupOnReject()
    MarkCommitted()
}

type signEffects struct {
    envelopes []tss.Envelope
}
```

Example for CGGMP presign:

```go
type presignTransition interface {
    Apply(st *cggmpPresignState) (presignEffects, error)
    CleanupOnReject()
    MarkCommitted()
}

type presignEffects struct {
    envelopes []tss.Envelope
}
```

## Tests

Add helper tests:

```text
frost/ed25519/session_helpers_test.go
cggmp21/secp256k1/session_helpers_test.go
```

Cover:

- `slot` valid/invalid behavior
- `partyTable` deterministic order
- `partyTable` lookup and missing party behavior
- `partyTable.All` / `Count` / `IDsWhere`
- `cleanupStack` LIFO ordering
- `cleanupStack.Disarm` prevents cleanup

## Acceptance criteria

- Helpers compile in both packages.
- Helper tests pass.
- No production protocol behavior changes are introduced.
- No public API changes.
- `STATUS.md` records whether helpers remain package-local after this phase.
