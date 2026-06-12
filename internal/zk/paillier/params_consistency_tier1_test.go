//go:build tier1

package paillier

import (
	"testing"
)

// TestDefaultSecurityParamsValues verifies that the production
// DefaultSecurityParams match their documented values. Any drift here
// changes the security model of all CGGMP proofs.

// TestCheckPaillierModulus verifies the minimum bit-length check on Paillier
// moduli.
func TestCheckPaillierModulus(t *testing.T) {
	t.Parallel()

	sp := DefaultSecurityParams()

	// Test with a key that meets the minimum (requires keygen)
	sk1024 := testPaillierKey(t, 1024)
	err := sp.CheckPaillierModulus(&sk1024.PublicKey)
	if err == nil {
		t.Error("DefaultSecurityParams should reject 1024-bit modulus (MinPaillierBits=3072)")
	}

	// FastSecurityParams should accept 1024-bit
	fast := FastSecurityParams()
	if err := fast.CheckPaillierModulus(&sk1024.PublicKey); err != nil {
		t.Errorf("FastSecurityParams rejected 1024-bit modulus: %v", err)
	}
}
