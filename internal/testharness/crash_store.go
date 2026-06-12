package testharness

// CrashPoint identifies where in the protocol lifecycle a simulated crash
// should be injected.
type CrashPoint int

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
