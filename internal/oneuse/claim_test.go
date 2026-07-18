package oneuse

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestClaimGuardLifecycle(t *testing.T) {
	t.Parallel()
	var guard ClaimGuard
	var inspected atomic.Int32
	if err := guard.WithAvailable(func() error {
		inspected.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("inspect available value: %v", err)
	}
	prepareErr := errors.New("prepare failed")
	if err := guard.Begin(func() error { return prepareErr }); !errors.Is(err, prepareErr) {
		t.Fatalf("Begin error = %v, want prepare failure", err)
	}
	if err := guard.Begin(nil); err != nil {
		t.Fatalf("claim after prepare failure: %v", err)
	}
	if err := guard.Begin(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second claim error = %v, want ErrUnavailable", err)
	}
	if err := guard.WithAvailable(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inspect claimed value error = %v, want ErrUnavailable", err)
	}
	guard.Rollback()
	if err := guard.Begin(nil); err != nil {
		t.Fatalf("claim after rollback: %v", err)
	}
	var destroyed atomic.Int32
	guard.Commit(func() { destroyed.Add(1) })
	guard.Destroy(func() { destroyed.Add(1) })
	if got := destroyed.Load(); got != 1 {
		t.Fatalf("destroy callback count = %d, want 1", got)
	}
	if err := guard.Begin(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("claim after commit error = %v, want ErrUnavailable", err)
	}
	if got := inspected.Load(); got != 1 {
		t.Fatalf("inspect callback count = %d, want 1", got)
	}
}

func TestClaimGuardConcurrentClaimHasOneWinner(t *testing.T) {
	t.Parallel()
	var guard ClaimGuard
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if guard.Begin(nil) == nil {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("claim winners = %d, want 1", got)
	}
}
