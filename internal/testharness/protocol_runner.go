package testharness

import (
	"testing"

	"github.com/islishude/tss"
)

// ProtocolCase is the interface every protocol test scenario implements.
// A single ProtocolCase covers one row of a table-driven test.
type ProtocolCase interface {
	// Name returns a descriptive name for the test case.
	Name() string

	// Start begins the protocol and returns the initial sessions and outbound messages.
	Start(t *testing.T) ([]Session, []tss.Envelope)

	// Step delivers one batch of envelopes and returns the next round's
	// messages, or an error if the protocol rejected the input.
	Step(t *testing.T, sessions []Session, envelopes []tss.Envelope) ([]tss.Envelope, error)

	// Done reports whether the protocol has completed successfully.
	Done(sessions []Session) bool

	// AssertSuccess verifies that the protocol completed with the expected results.
	AssertSuccess(t *testing.T, sessions []Session)

	// AssertFailClosed verifies that a reject path left state unchanged.
	AssertFailClosed(t *testing.T, before, after StateSnapshot)
}

// Session wraps a protocol session with its party identity.
type Session struct {
	PartyID tss.PartyID

	// Outbox returns the current outbound envelope queue.
	Outbox func() []tss.Envelope
}

// ProtocolResult captures the outcome of delivering a set of envelopes
// through the protocol runner.
type ProtocolResult struct {
	Err      error
	Outbox   []tss.Envelope
	Advanced bool
}

// Run executes a ProtocolCase through its full lifecycle and returns
// an error on the first failure.
func Run(t *testing.T, c ProtocolCase) {
	t.Helper()

	sessions, envelopes := c.Start(t)

	for !c.Done(sessions) {
		next, err := c.Step(t, sessions, envelopes)
		if err != nil {
			t.Fatalf("protocol step: %v", err)
		}
		envelopes = next
	}

	c.AssertSuccess(t, sessions)
}
