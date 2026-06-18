//go:build integration

package secp256k1

import "testing"

func BenchmarkCGGMP21KeygenFull2of3(b *testing.B) {
	for b.Loop() {
		_ = secpKeygen(b, 2, 3)
	}
}

func BenchmarkCGGMP21KeygenFull3of5(b *testing.B) {
	for b.Loop() {
		_ = secpKeygen(b, 3, 5)
	}
}
