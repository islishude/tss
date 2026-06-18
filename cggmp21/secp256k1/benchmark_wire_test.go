//go:build integration

package secp256k1

import (
	"testing"
)

// Serialization: envelope and key share encode/decode.

func BenchmarkCGGMP21WireKeyShareRoundTrip(b *testing.B) {
	shares := CachedKeygenShares(b, 2, 3)
	var ks KeyShare
	for _, v := range shares {
		ks = *v
		break
	}

	for b.Loop() {
		raw, err := ks.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := UnmarshalKeyShare(raw); err != nil {
			b.Fatal(err)
		}
	}
}
