package paillier

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	pai "github.com/islishude/tss/internal/paillier"
)

// SecurityParams collects the statistical and computational security parameters
// used by CGGMP-compatible Paillier range proofs. Every verifier must check that
// the prover is using matching parameters; proofs that do not bind these values
// into the Fiat-Shamir challenge are rejected.
type SecurityParams struct {
	// Ell is the curve scalar bit length. For secp256k1: 256.
	Ell uint

	// EllPrime is the secondary plaintext range for affine operations.
	// For CGGMP affine proofs this is larger than Ell (typically 848).
	EllPrime uint

	// Epsilon is the statistical slack for zero-knowledge.
	// Masks are sampled from ±2^(rangeBit+Epsilon) to statistically hide the witness.
	Epsilon uint

	// ChallengeBits is the Fiat-Shamir challenge bit length.
	// 128 bits provides 128-bit soundness.
	ChallengeBits uint

	// MinPaillierBits is the Paillier modulus security floor.
	// 3072 bits provides ~128-bit classical security matching secp256k1.
	MinPaillierBits int
}

// DefaultSecurityParams returns the production CGGMP security parameters for
// secp256k1 with 128-bit statistical and computational security.
//
//	Ell   = 256   (secp256k1 scalar bit length)
//	EllPrime = 848 (affine secondary range, per CGGMP parameter set)
//	Epsilon  = 230  (statistical slack ~2^230)
//	ChallengeBits = 128 (128-bit soundness)
//	MinPaillierBits = 3072 (NIST SP 800-57 alignment)
func DefaultSecurityParams() SecurityParams {
	return SecurityParams{
		Ell:             256,
		EllPrime:        848,
		Epsilon:         230,
		ChallengeBits:   128,
		MinPaillierBits: 3072,
	}
}

// FastSecurityParams returns reduced security parameters suitable for
// fast test-only proof generation. These do NOT provide production security.
func FastSecurityParams() SecurityParams {
	return SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
}

// Validate checks that all security parameters are within acceptable bounds.
func (sp SecurityParams) Validate() error {
	if sp.Ell == 0 {
		return errors.New("SecurityParams.Ell must be positive")
	}
	if sp.EllPrime == 0 {
		return errors.New("SecurityParams.EllPrime must be positive")
	}
	if sp.Epsilon == 0 {
		return errors.New("SecurityParams.Epsilon must be positive")
	}
	if sp.ChallengeBits == 0 || sp.ChallengeBits > 256 {
		return errors.New("SecurityParams.ChallengeBits must be in [1, 256]")
	}
	if sp.MinPaillierBits <= 0 {
		return errors.New("SecurityParams.MinPaillierBits must be positive")
	}
	return nil
}

// CheckPaillierModulus verifies that a Paillier modulus N satisfies the minimum
// bit-length requirement from the security parameters.
func (sp SecurityParams) CheckPaillierModulus(n *pai.PublicKey) error {
	if n == nil || n.N == nil {
		return errors.New("nil Paillier public key")
	}
	bits := n.N.BitLen()
	if bits < sp.MinPaillierBits {
		return fmt.Errorf("paillier modulus is %d bits, minimum is %d", bits, sp.MinPaillierBits)
	}
	return nil
}

// EncRange returns the mask range for encryption/range proofs: Ell + max(Epsilon, ChallengeBits).
func (sp SecurityParams) EncRange() uint {
	bonus := max(sp.ChallengeBits, sp.Epsilon)
	return sp.Ell + bonus
}

// AffGRange returns the mask range for affine proofs: EllPrime + max(Epsilon, ChallengeBits).
func (sp SecurityParams) AffGRange() uint {
	bonus := max(sp.ChallengeBits, sp.Epsilon)
	return sp.EllPrime + bonus
}

// overrideSecurityParams allows tests to replace the global security parameters.
// Nil means use DefaultSecurityParams. Protected by paramsMu.
//
// Callers must use [SetSecurityParamsForTesting] to set this and call the
// returned restore function to undo the override. Do NOT set this field directly.
var (
	overrideSecurityParams *SecurityParams
	paramsMu               sync.Mutex
)

// SetSecurityParamsForTesting overrides the global security parameters and
// returns a function that restores the previous value.
//
// IMPORTANT: SetSecurityParamsForTesting must only be called from TestMain
// or from sequential (non-parallel) test functions. Calling it from tests that
// use t.Parallel() may cause data races with other packages that also override
// security parameters. The returned restore function must be called before the
// test returns (use t.Cleanup or defer).
//
// SetSecurityParamsForTesting panics if called outside of tests. Production
// code always uses [DefaultSecurityParams].
//
// Example (TestMain):
//
//	func TestMain(m *testing.M) {
//	    restore := zkpai.SetSecurityParamsForTesting(zkpai.FastSecurityParams())
//	    code := m.Run()
//	    restore()
//	    os.Exit(code)
//	}
//
// Example (sequential test):
//
//	func TestFoo(t *testing.T) {
//	    restore := zkpai.SetSecurityParamsForTesting(zkpai.SecurityParams{...})
//	    defer restore()
//	    // ... test body ...
//	}
func SetSecurityParamsForTesting(sp SecurityParams) func() {
	if !testing.Testing() {
		panic("SetSecurityParamsForTesting called outside of tests — production code must use DefaultSecurityParams")
	}
	paramsMu.Lock()
	old := overrideSecurityParams
	spCopy := sp
	overrideSecurityParams = &spCopy
	paramsMu.Unlock()
	return func() {
		paramsMu.Lock()
		overrideSecurityParams = old
		paramsMu.Unlock()
	}
}

// ActiveSecurityParams returns the currently active security parameters.
// In production this is [DefaultSecurityParams]; in tests it reflects the most
// recent call to [SetSecurityParamsForTesting].
func ActiveSecurityParams() SecurityParams {
	paramsMu.Lock()
	defer paramsMu.Unlock()
	if overrideSecurityParams != nil {
		return *overrideSecurityParams
	}
	return DefaultSecurityParams()
}
