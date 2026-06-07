//go:build integration || vectorgen

package secp256k1

import (
	"os"
	"testing"

	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestMain(m *testing.M) {
	restoreSP := zkpai.SetSecurityParamsForTesting(zkpai.SecurityParams{
		Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 768,
	})
	code := m.Run()
	restoreSP()
	os.Exit(code)
}
