package ed25519

import "testing"

// Offline: key generation (DKG).

func BenchmarkFROSTKeygen2of3(b *testing.B) {
	for b.Loop() {
		shares := cachedFrostKeygen(b, 2, 3, false)
		_ = shares
	}
}

func BenchmarkFROSTKeygen3of5(b *testing.B) {
	for b.Loop() {
		shares := cachedFrostKeygen(b, 3, 5, false)
		_ = shares
	}
}
