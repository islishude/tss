package testharness

import "testing"

// StateSnapshot captures the externally observable state of a protocol session
// at a point in time. It must not contain secret-bearing fields.
type StateSnapshot struct {
	Round     int
	OutboxLen int
	Consumed  bool
	Completed bool
}

// Snapshotter is the interface that protocol sessions must implement to
// support state capture for fail-closed assertions.
type Snapshotter interface {
	CurrentRound() int
	OutboxCount() int
	IsConsumed() bool
	IsComplete() bool
}

// CaptureSnapshot captures the current externally observable state.
func CaptureSnapshot(s Snapshotter) StateSnapshot {
	return StateSnapshot{
		Round:     s.CurrentRound(),
		OutboxLen: s.OutboxCount(),
		Consumed:  s.IsConsumed(),
		Completed: s.IsComplete(),
	}
}

// AssertNoSideEffect fails if any tracked field changed between before and
// after. Use after delivering a rejected message to verify fail-closed behavior.
func AssertNoSideEffect(t *testing.T, before, after StateSnapshot) {
	t.Helper()
	if before.Round != after.Round {
		t.Errorf("round changed from %d to %d on rejected input", before.Round, after.Round)
	}
	if after.OutboxLen != before.OutboxLen {
		t.Errorf("outbox changed from %d to %d on rejected input", before.OutboxLen, after.OutboxLen)
	}
	if after.Consumed && !before.Consumed {
		t.Errorf("consumed flag set on rejected input")
	}
}
