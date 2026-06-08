package ed25519

import (
	"github.com/islishude/tss"
)

// DefaultLimits returns fail-closed production limits for FROST Ed25519.
// It rejects 1-of-1, oversized signer sets, and thresholds below 2.
// Test code must use TestLimits or SetLimitsForTesting to relax these
// constraints.
func DefaultLimits() tss.Limits {
	if overrideLimits != nil {
		return *overrideLimits
	}
	l := tss.DefaultLimits()
	l.MaxParties = tss.MaxFROSTParties
	l.MaxThreshold = tss.MaxFROSTThreshold
	l.MaxSigners = tss.MaxFROSTSigners
	return l
}

// TestLimits returns relaxed limits for FROST Ed25519 test code only.
// 1-of-1 and oversized signer sets are allowed. NEVER use these limits in
// production entry points.
func TestLimits() tss.Limits {
	l := DefaultLimits()
	l.MaxParties = 8
	l.MaxThreshold = 8
	l.MaxSigners = 8
	l.AllowOneOfOne = true
	l.MinProductionThreshold = 1
	l.AllowOversizedSignerSet = true
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
