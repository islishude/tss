package paillier

import (
	"errors"
	"fmt"
	"sync"

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
var (
	overrideSecurityParams *SecurityParams
	paramsMu               sync.Mutex
)

// SetSecurityParamsForTesting overrides the global security parameters and
// returns a function that restores the previous value. DO NOT use outside tests.
//
// The returned restore function is safe to use with t.Cleanup:
//
//	t.Cleanup(zkpai.SetSecurityParamsForTesting(zkpai.FastSecurityParams()))
func SetSecurityParamsForTesting(sp SecurityParams) func() {
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
func ActiveSecurityParams() SecurityParams {
	paramsMu.Lock()
	defer paramsMu.Unlock()
	if overrideSecurityParams != nil {
		return *overrideSecurityParams
	}
	return DefaultSecurityParams()
}
