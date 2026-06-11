package mta

import (
	"os"
	"testing"

	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// TestMain applies reduced Paillier modulus requirements so that Tier 1 tests
// can use 1024-bit test keys without tripping production minimums (3072-bit).
//
// SetSecurityParamsForTesting must only be called from TestMain or sequential
// tests; calling it from parallel tests creates a data race on the global
// overrideSecurityParams.
func TestMain(m *testing.M) {
	restoreSP := zkpai.SetSecurityParamsForTesting(zkpai.FastSecurityParams())
	code := m.Run()
	restoreSP()
	os.Exit(code)
}
