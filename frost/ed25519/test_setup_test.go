package ed25519

import (
	"os"
	"testing"
)

// TestMain applies relaxed test limits to all tests and examples in this
// package. Production entry points are fail-closed; tests must explicitly
// opt into permissive limits via SetLimitsForTesting.
func TestMain(m *testing.M) {
	restore := SetLimitsForTesting(TestLimits())
	code := m.Run()
	restore()
	os.Exit(code)
}
