package ed25519

import (
	"testing"

	"github.com/islishude/tss"
)

func frostKeygenHD(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	return cachedFrostKeygen(t, threshold, n)
}
