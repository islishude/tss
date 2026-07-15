package testharness

import (
	"bytes"
	"errors"
	"sync"
)

// CrashPoint identifies where in the protocol lifecycle a simulated crash
// should be injected.
type CrashPoint int

// CrashDisabled disables fault injection for a CrashyStore.
const CrashDisabled CrashPoint = -1

const (
	// CrashBeforePersist aborts before persisting newly-generated state.
	CrashBeforePersist CrashPoint = iota
	// CrashAfterPersist aborts after state is persisted but before the next
	// protocol action completes.
	CrashAfterPersist
	// CrashBeforeOutbound aborts after constructing outbound messages but
	// before they are emitted to the network.
	CrashBeforeOutbound
	// CrashAfterOutbound aborts after outbound messages have been emitted
	// but before the next round begins.
	CrashAfterOutbound
)

var (
	// ErrCrashInjected reports that a CrashyStore reached its configured crash point.
	ErrCrashInjected = errors.New("testharness: injected crash")
	// ErrCrashStoreConflict reports that CompareAndSwap did not find the expected blob.
	ErrCrashStoreConflict = errors.New("testharness: crash store compare-and-swap conflict")
)

// CrashyStore is an in-memory single-blob store with one-shot crash injection.
// It is intended only for crash/restart tests involving serialized secret state.
// Stored and returned byte slices are always independently owned.
type CrashyStore struct {
	mu        sync.Mutex
	blob      []byte
	crashAt   CrashPoint
	triggered bool
}

// NewCrashyStore returns a store containing an independently owned copy of initial.
func NewCrashyStore(initial []byte, crashAt CrashPoint) *CrashyStore {
	return &CrashyStore{blob: bytes.Clone(initial), crashAt: crashAt}
}

// Load returns an independently owned copy of the current durable blob.
func (s *CrashyStore) Load() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.blob)
}

// CompareAndSwap replaces expected with next atomically. It takes ownership of
// next and clears that caller-provided slice before returning on every path. A
// configured CrashBeforePersist leaves the old blob installed;
// CrashAfterPersist installs an independently owned copy of the new blob before
// returning ErrCrashInjected.
func (s *CrashyStore) CompareAndSwap(expected, next []byte) error {
	if s == nil {
		clear(next)
		return errors.New("testharness: nil crash store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !bytes.Equal(s.blob, expected) {
		clear(next)
		return ErrCrashStoreConflict
	}
	if s.hitLocked(CrashBeforePersist) {
		clear(next)
		return ErrCrashInjected
	}
	replacement := bytes.Clone(next)
	clear(next)
	clear(s.blob)
	s.blob = replacement
	if s.hitLocked(CrashAfterPersist) {
		return ErrCrashInjected
	}
	return nil
}

// Hit returns ErrCrashInjected once when point matches the configured crash point.
// Tests call Hit around outbound effects; persistence points are invoked by
// CompareAndSwap itself.
func (s *CrashyStore) Hit(point CrashPoint) error {
	if s == nil {
		return errors.New("testharness: nil crash store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hitLocked(point) {
		return ErrCrashInjected
	}
	return nil
}

func (s *CrashyStore) hitLocked(point CrashPoint) bool {
	if s.triggered || s.crashAt == CrashDisabled || s.crashAt != point {
		return false
	}
	s.triggered = true
	return true
}

// Destroy clears the retained blob and disables further fault injection.
func (s *CrashyStore) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.blob)
	s.blob = nil
	s.crashAt = CrashDisabled
	s.triggered = true
}
