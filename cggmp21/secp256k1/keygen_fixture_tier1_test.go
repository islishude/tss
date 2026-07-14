//go:build tier1

package secp256k1

import (
	"fmt"
	"testing"
)

func TestTier1_CGGMP21_KeygenFixtures_AreCompleteValidAndCanonical(t *testing.T) {
	for _, key := range requiredKeygenFixtureOrder {
		t.Run(fmt.Sprintf("%d-of-%d", key.threshold, key.n), func(t *testing.T) {
			shares, ok, err := loadKeygenFixture(key.threshold, key.n)
			if err != nil {
				t.Fatal(err)
			}
			for _, share := range shares {
				defer share.Destroy()
			}
			if !ok {
				t.Fatalf("missing fixture for %d-of-%d", key.threshold, key.n)
			}
			if len(shares) != key.n {
				t.Fatalf("got %d shares, want %d", len(shares), key.n)
			}
		})
	}
}

func TestTier1_CGGMP21_KeygenFixtures_ReturnIndependentClones(t *testing.T) {
	a := CachedKeygenShares(t, 2, 3)
	b := CachedKeygenShares(t, 2, 3)

	if a[1] == b[1] {
		t.Fatal("expected independent KeyShare pointers")
	}

	a[1].state.PublicKey[0] ^= 1
	a[1].state.ChainCode[0] ^= 1
	a[1].state.Parties[0] = 99

	if err := b[1].ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("second clone was affected by first clone mutation: %v", err)
	}

	c := CachedKeygenShares(t, 2, 3)
	if err := c[1].ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("cache was polluted: %v", err)
	}
}
