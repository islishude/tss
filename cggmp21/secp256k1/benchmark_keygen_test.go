//go:build integration

package secp256k1

import "testing"

// Offline: key generation (full DKG).

func BenchmarkCGGMP21Keygen2of3(b *testing.B) {
	for b.Loop() {
		_ = CachedKeygenShares(b, 2, 3, false)
	}
}

func BenchmarkCGGMP21Keygen3of5(b *testing.B) {
	for b.Loop() {
		_ = CachedKeygenShares(b, 3, 5, false)
	}
}

// BenchmarkCGGMP21KeygenHD tests keygen with HD chain code enabled.
func BenchmarkCGGMP21KeygenHD2of3(b *testing.B) {
	for b.Loop() {
		_ = CachedKeygenShares(b, 2, 3, true)
	}
}
