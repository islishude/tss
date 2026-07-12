package paillier

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
)

const (
	securityParamsWireType    = "zk.paillier.security-params"
	securityParamsWireVersion = 1
)

const (
	maxSecurityParameterBits uint32 = tss.DefaultMaxPaillierModulusBits
	proofResponseSlackBits   uint32 = 2
	// Πdec reconstructs a sum of pairwise affine terms before multiplying by
	// an ECDSA scalar. This covers aggregation carry bits for the protocol's
	// bounded signer set instead of assuming a single EllPrime-bit term.
	decAggregationSlackBits uint32 = 16
)

// SecurityParams collects the statistical and computational security parameters
// used by CGGMP-compatible Paillier range proofs. Every verifier must check that
// the prover is using matching parameters; proofs that do not bind these values
// into the Fiat-Shamir challenge are rejected.
type SecurityParams struct {
	// Ell is the curve scalar bit length. For secp256k1: 256.
	Ell uint32 `wire:"1,u32"`

	// EllPrime is the secondary plaintext range for affine operations.
	// For CGGMP affine proofs this is larger than Ell (typically 848).
	EllPrime uint32 `wire:"2,u32"`

	// Epsilon is the statistical slack for zero-knowledge.
	// Masks are sampled from ±2^(rangeBit+Epsilon) to statistically hide the witness.
	Epsilon uint32 `wire:"3,u32"`

	// ChallengeBits is the Fiat-Shamir challenge bit length.
	// 128 bits provides 128-bit soundness.
	ChallengeBits uint32 `wire:"4,u32"`

	// MinPaillierBits is the Paillier and Ring-Pedersen auxiliary modulus
	// security floor. 3072 bits provides ~128-bit classical security matching
	// secp256k1.
	MinPaillierBits uint32 `wire:"5,u32"`
}

// WireType returns the canonical wire type identifier for SecurityParams.
func (SecurityParams) WireType() string { return securityParamsWireType }

// WireVersion returns the wire format version for SecurityParams.
func (SecurityParams) WireVersion() uint16 { return securityParamsWireVersion }

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
	if sp.MinPaillierBits < pai.MinModulusBits {
		return fmt.Errorf("SecurityParams.MinPaillierBits must be at least %d", pai.MinModulusBits)
	}
	if sp.MinPaillierBits > maxSecurityParameterBits {
		return fmt.Errorf("SecurityParams.MinPaillierBits must not exceed %d", maxSecurityParameterBits)
	}
	bonus := max(sp.ChallengeBits, sp.Epsilon)
	maxRange := maxSecurityParameterBits - proofResponseSlackBits
	if bonus > maxRange {
		return fmt.Errorf("SecurityParams range bonus must not exceed %d", maxRange)
	}
	if sp.Ell > maxRange-bonus {
		return fmt.Errorf("SecurityParams encryption range must not exceed %d bits", maxRange)
	}
	if sp.EllPrime > maxRange-bonus {
		return fmt.Errorf("SecurityParams affine range must not exceed %d bits", maxRange)
	}
	if sp.Ell > maxRange-sp.EllPrime || bonus > maxRange-sp.EllPrime-sp.Ell {
		return fmt.Errorf("SecurityParams decryption range must not exceed %d bits", maxRange)
	}
	return nil
}

// MarshalBinary encodes the security profile using canonical TLV.
func (sp SecurityParams) MarshalBinary() ([]byte, error) {
	return wire.Marshal(sp)
}

// UnmarshalBinary decodes and validates a canonical security profile.
func (sp *SecurityParams) UnmarshalBinary(in []byte) error {
	var decoded SecurityParams
	if err := wire.Unmarshal(in, &decoded); err != nil {
		return err
	}
	*sp = decoded
	return nil
}

// CheckPaillierModulus verifies that a Paillier modulus N satisfies the minimum
// bit-length requirement from the security parameters.
func (sp SecurityParams) CheckPaillierModulus(n *pai.PublicKey) error {
	if n == nil || n.N == nil {
		return errors.New("nil Paillier public key")
	}
	bits := n.N.BitLen()
	if bits < int(sp.MinPaillierBits) {
		return fmt.Errorf("paillier modulus is %d bits, minimum is %d", bits, sp.MinPaillierBits)
	}
	return nil
}

// CheckRingPedersenModulus verifies that a Ring-Pedersen auxiliary modulus
// satisfies the minimum bit-length requirement from the security parameters.
func (sp SecurityParams) CheckRingPedersenModulus(n *big.Int) error {
	if n == nil {
		return errors.New("nil Ring-Pedersen modulus")
	}
	bits := n.BitLen()
	if bits < int(sp.MinPaillierBits) {
		return fmt.Errorf("Ring-Pedersen modulus is %d bits, minimum is %d", bits, sp.MinPaillierBits)
	}
	return nil
}

// EncRange returns the mask range for encryption/range proofs: Ell + max(Epsilon, ChallengeBits).
func (sp SecurityParams) EncRange() uint32 {
	bonus := max(sp.ChallengeBits, sp.Epsilon)
	return boundedProofRange(sp.Ell, bonus)
}

// AffGRange returns the mask range for affine proofs: EllPrime + max(Epsilon, ChallengeBits).
func (sp SecurityParams) AffGRange() uint32 {
	bonus := max(sp.ChallengeBits, sp.Epsilon)
	return boundedProofRange(sp.EllPrime, bonus)
}

// DecPlaintextRange returns the public bound for online decryption witnesses.
// The sigma ciphertext contains an affine plaintext multiplied by an ECDSA
// scalar and sums multiple pairwise terms, so its bound includes conservative
// aggregation carry slack in addition to EllPrime + Ell.
func (sp SecurityParams) DecPlaintextRange() uint32 {
	return boundedProofRange(sp.EllPrime, sp.Ell+decAggregationSlackBits)
}

// DecRange returns the response-mask bound for Πdec.
func (sp SecurityParams) DecRange() uint32 {
	return sp.DecPlaintextRange() + max(sp.Epsilon, sp.ChallengeBits)
}

func boundedProofRange(base, bonus uint32) uint32 {
	if bonus > maxSecurityParameterBits || base > maxSecurityParameterBits-bonus {
		return maxSecurityParameterBits
	}
	return base + bonus
}
