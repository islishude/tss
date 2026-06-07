//go:build integration || vectorgen

package secp256k1

import (
	"os"
	"testing"

	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestMain(m *testing.M) {
	restore := zkpai.SetSecurityParamsForTesting(zkpai.FastSecurityParams())
	code := m.Run()
	restore()
	os.Exit(code)
}
