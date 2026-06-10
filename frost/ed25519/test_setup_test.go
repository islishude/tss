package ed25519

import (
	"os"
	"testing"
)

// TestMain applies relaxed test limits so that all tests and examples in this
// package can exercise 1-of-1 and other non-production configurations without
// setting limits explicitly on every Options struct.
// Production entry points remain fail-closed because testDefaultLimits is only
// set by TestMain and never touches production code.
func TestMain(m *testing.M) {
	tl := TestLimits()
	testDefaultLimits = &tl
	code := m.Run()
	testDefaultLimits = nil
	os.Exit(code)
}
