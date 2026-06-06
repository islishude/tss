//go:build integration || vectorgen

package secp256k1

import (
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	restoreBits := SetDefaultPaillierBitsForTesting(768)
	restoreMin := pai.SetMinimumModulusBitsForTesting(512)
	restoreKeygenMin := SetMinKeygenPaillierBitsForTesting(768)
	restoreSign := SetAcceptExperimentalUsageForTesting(true)
	restoreSP := zkpai.SetSecurityParamsForTesting(zkpai.SecurityParams{
		Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512,
	})
	code := m.Run()
	restoreBits()
	restoreMin()
	restoreKeygenMin()
	restoreSign()
	restoreSP()
	os.Exit(code)
}
