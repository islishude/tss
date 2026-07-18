// Package oneuse provides small lifecycle guards for secret-bearing values
// that may be claimed once and must be destroyed when consumed.
package oneuse

import (
	"errors"
	"sync"
)

// ErrUnavailable reports that a value is already claimed or consumed.
var ErrUnavailable = errors.New("one-use value already claimed or consumed")

const (
	stateAvailable uint8 = iota
	stateClaimed
	stateConsumed
)

// ClaimGuard serializes the available -> claimed -> consumed lifecycle. The
// zero value is available and ready for use.
type ClaimGuard struct {
	mu    sync.Mutex
	state uint8
}

// WithAvailable runs inspect while exclusively owning an available value. It
// does not change the lifecycle state.
func (g *ClaimGuard) WithAvailable(inspect func() error) error {
	if g == nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != stateAvailable {
		return ErrUnavailable
	}
	if inspect == nil {
		return nil
	}
	return inspect()
}

// Begin runs prepare while exclusively owning an available value and marks it
// claimed only when prepare succeeds.
func (g *ClaimGuard) Begin(prepare func() error) error {
	if g == nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != stateAvailable {
		return ErrUnavailable
	}
	if prepare != nil {
		if err := prepare(); err != nil {
			return err
		}
	}
	g.state = stateClaimed
	return nil
}

// Rollback makes an in-progress claim available again. It has no effect after
// commit or destruction.
func (g *ClaimGuard) Rollback() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == stateClaimed {
		g.state = stateAvailable
	}
}

// Commit consumes an in-progress claim and runs destroy while holding the
// lifecycle lock. It has no effect unless Begin previously succeeded.
func (g *ClaimGuard) Commit(destroy func()) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != stateClaimed {
		return
	}
	g.state = stateConsumed
	if destroy != nil {
		destroy()
	}
}

// Destroy permanently consumes the value and runs destroy at most once.
func (g *ClaimGuard) Destroy(destroy func()) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == stateConsumed {
		return
	}
	g.state = stateConsumed
	if destroy != nil {
		destroy()
	}
}
