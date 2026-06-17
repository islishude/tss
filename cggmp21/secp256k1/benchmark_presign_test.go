//go:build integration

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
)

// Offline: pre-compute before signing.

func BenchmarkCGGMP21Presign2of3(b *testing.B) {
	shares := CachedKeygenShares(b, 2, 3, false)
	signers := tss.NewPartySet(1, 2)

	for b.Loop() {
		secpPresign(b, shares, signers)
	}
}

func BenchmarkCGGMP21Presign3of5(b *testing.B) {
	shares := CachedKeygenShares(b, 3, 5, false)
	signers := tss.NewPartySet(1, 3, 5)

	for b.Loop() {
		secpPresign(b, shares, signers)
	}
}
