package bip32util

import (
	"fmt"

	"github.com/islishude/tss"
)

// AggregateChainCode XORs the 32-byte chain code from each party to produce the
// group chain code. The caller is responsible for checking whether HD is enabled;
// this function requires every party to contribute exactly 32 bytes.
func AggregateChainCode(parties []tss.PartyID, chainCodes map[tss.PartyID][]byte) ([]byte, error) {
	out := make([]byte, 32)
	for _, id := range parties {
		if len(chainCodes[id]) != 32 {
			return nil, fmt.Errorf("party %d chain code is %d bytes, want 32", id, len(chainCodes[id]))
		}
		for i := range out {
			out[i] ^= chainCodes[id][i]
		}
	}
	return out, nil
}
