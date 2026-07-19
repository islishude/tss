// Package testharness provides reusable test infrastructure for TSS protocol
// tests: deterministic RNG, party factories, envelope mutation, network fault
// simulation, state snapshots, protocol runners, and crash-store helpers.
package testharness

import (
	"io"
	"testing"

	"github.com/islishude/tss/internal/testutil"
)

// Reader returns a deterministic io.Reader for the calling test. The seed is
// printed via t.Logf so CI failures are reproducible. When TSS_TEST_SEED is
// set in the environment, it overrides the default seed of 42.
func Reader(t *testing.T) io.Reader {
	t.Helper()
	return testutil.DeterministicReaderFromEnv(t, 42)
}
