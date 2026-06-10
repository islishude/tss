//go:build integration || vectorgen

package secp256k1

import (
	"os"
	"testing"

	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestMain(m *testing.M) {
	restoreSP := zkpai.SetSecurityParamsForTesting(zkpai.FastSecurityParams())
	// Integration tests use reduced Paillier moduli (768-bit) and may
	// test 1-of-1 flows — apply relaxed limits.
	tl := TestLimits()
	testDefaultLimits = &tl
	code := m.Run()
	testDefaultLimits = nil
	restoreSP()
	os.Exit(code)
}
