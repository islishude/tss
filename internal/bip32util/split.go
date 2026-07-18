package bip32util

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
)

// SplitChainCode creates per-party XOR shares whose canonical aggregation is
// target. Returned shares are independently owned by the caller and should be
// cleared after use when they are treated as confidential contribution data.
func SplitChainCode(reader io.Reader, target []byte, parties tss.PartySet) (map[tss.PartyID][]byte, error) {
	if reader == nil {
		return nil, errors.New("nil chain-code randomness reader")
	}
	if len(target) != ChainCodeSize {
		return nil, fmt.Errorf("chain code must be %d bytes", ChainCodeSize)
	}
	if len(parties) == 0 {
		return nil, errors.New("chain-code parties must not be empty")
	}
	seen := make(map[tss.PartyID]struct{}, len(parties))
	for _, party := range parties {
		if party == tss.BroadcastPartyId {
			return nil, errors.New("chain-code party must not be zero")
		}
		if _, ok := seen[party]; ok {
			return nil, fmt.Errorf("duplicate chain-code party %d", party)
		}
		seen[party] = struct{}{}
	}

	out := make(map[tss.PartyID][]byte, len(parties))
	remaining := bytes.Clone(target)
	for i, party := range parties {
		share := make([]byte, ChainCodeSize)
		if i < len(parties)-1 {
			if _, err := io.ReadFull(reader, share); err != nil {
				clear(share)
				clear(remaining)
				for _, value := range out {
					clear(value)
				}
				return nil, err
			}
			for j := range remaining {
				remaining[j] ^= share[j]
			}
		} else {
			copy(share, remaining)
		}
		out[party] = share
	}
	clear(remaining)
	return out, nil
}
