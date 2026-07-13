package tssrun_test

import (
	"os"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
	"github.com/islishude/tss/tssrun/conformance"
)

func TestFileLifecycleStoreConformance(t *testing.T) {
	params := &tss.PassphraseParams{Time: 1, Memory: 1024, Threads: 1}
	conformance.RunConformance(t, conformance.Harness{
		NewLifecycleStore: func(tb testing.TB) tssrun.LifecycleStore {
			tb.Helper()
			directory := tb.TempDir()
			// #nosec G302 -- 0700 is required for a traversable private directory.
			if err := os.Chmod(directory, 0o700); err != nil {
				tb.Fatalf("Chmod lifecycle test directory: %v", err)
			}
			store, err := tssrun.NewFileLifecycleStore(directory, []byte("file-lifecycle-conformance-passphrase"), params)
			if err != nil {
				tb.Fatalf("NewFileLifecycleStore: %v", err)
			}
			tb.Cleanup(func() {
				if err := store.Close(); err != nil {
					tb.Errorf("Close FileLifecycleStore: %v", err)
				}
			})
			return store
		},
	})
}
