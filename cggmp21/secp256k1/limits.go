package secp256k1

import (
	"github.com/islishude/tss"
)

// DefaultLimits returns fail-closed production limits for CGGMP21 secp256k1.
// It rejects 1-of-1, oversized signer sets, Paillier moduli below 3072 bits,
// and thresholds below 2. Test code must use TestLimits or
// SetLimitsForTesting to relax these constraints.
func DefaultLimits() tss.Limits {
	if overrideLimits != nil {
		return *overrideLimits
	}
	l := tss.DefaultLimits()
	l.MaxParties = tss.MaxCGGMPParties
	l.MaxThreshold = tss.MaxCGGMPThreshold
	l.MaxSigners = tss.MaxCGGMPSigners
	return l
}

// TestLimits returns relaxed limits for CGGMP21 test code only.
// Paillier moduli down to 512 bits, 1-of-1, and oversized signer sets are
// allowed. NEVER use these limits in production entry points.
func TestLimits() tss.Limits {
	l := DefaultLimits()
	l.MaxParties = 8
	l.MaxThreshold = 8
	l.MaxSigners = 8
	l.AllowOneOfOne = true
	l.MinProductionThreshold = 1
	l.AllowOversizedSignerSet = true
	l.MinPaillierModulusBits = 512
	l.MaxPaillierModulusBits = 8192
	l.MaxPaillierPublicKeyBytes = 4096
	l.MaxPaillierPrivateKeyBytes = 8192
	l.MaxPaillierCiphertextBytes = 4096
	l.MaxPaillierProofBytes = 512 << 10
	l.MaxRingPedersenParamsBytes = 16384
	l.MaxMTAResponseBytes = 512 << 10
	l.MaxZKProofBytes = 512 << 10
	return l
}

// overrideLimits allows tests to replace the limits returned by DefaultLimits.
// Nil means use the production default.
var overrideLimits *tss.Limits

// SetLimitsForTesting overrides the limits returned by DefaultLimits and
// returns a function that restores the production defaults. DO NOT use
// outside tests.
func SetLimitsForTesting(l tss.Limits) func() {
	old := overrideLimits
	lc := l
	overrideLimits = &lc
	return func() { overrideLimits = old }
}
