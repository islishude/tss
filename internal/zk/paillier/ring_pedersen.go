package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	transcriptpkg "github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

// RPCommit computes the Ring-Pedersen commitment: S^x * T^mu mod N.
// Both x and mu may be negative; negative exponents are handled via
// modular inverse.
func RPCommit(params RingPedersenParams, x, mu *big.Int) (*big.Int, error) {
	if err := validateRPParamsForCommit(params); err != nil {
		return nil, err
	}
	return MultiExpSignedMod(params.S, x, params.T, mu, params.N)
}

// RPCommitCT computes the Ring-Pedersen commitment using fixed-width
// constant-time exponentiation for secret witness and mask exponents.
func RPCommitCT(params RingPedersenParams, x, mu *secret.SignedInt, expLen int) (*big.Int, error) {
	if err := validateRPParamsForCommit(params); err != nil {
		return nil, err
	}
	if expLen <= 0 {
		return nil, errors.New("invalid RPCommitCT exponent length")
	}
	modLen := modulusBytes(params.N)
	r1, err := ExpSignedModCT(params.N, params.S, x, modLen, expLen)
	if err != nil {
		return nil, fmt.Errorf("RPCommitCT first term: %w", err)
	}
	r2, err := ExpSignedModCT(params.N, params.T, mu, modLen, expLen)
	if err != nil {
		return nil, fmt.Errorf("RPCommitCT second term: %w", err)
	}
	result := new(big.Int).Mul(r1, r2)
	result.Mod(result, params.N)
	return result, nil
}

// ExpSignedMod computes base^exp mod modulus, handling negative exponents
// via modular inverse of the base.
func ExpSignedMod(base, exp, modulus *big.Int) (*big.Int, error) {
	if base == nil || exp == nil || modulus == nil {
		return nil, errors.New("nil ExpSignedMod input")
	}
	if modulus.Sign() <= 0 {
		return nil, errors.New("invalid ExpSignedMod modulus")
	}

	e := new(big.Int).Set(exp)
	b := new(big.Int).Set(base)

	if e.Sign() < 0 {
		e.Neg(e)
		b.ModInverse(b, modulus)
		if b == nil {
			return nil, errors.New("base is not invertible modulo modulus for negative exponent")
		}
	}

	// For base ≡ 1 (mod modulus), Exp is trivial; avoid unnecessary work.
	result := new(big.Int).Exp(b, e, modulus)
	return result, nil
}

// MultiExpSignedMod computes base1^exp1 * base2^exp2 mod modulus, handling
// negative exponents via modular inverse.
func MultiExpSignedMod(base1, exp1, base2, exp2, modulus *big.Int) (*big.Int, error) {
	if base1 == nil || exp1 == nil || base2 == nil || exp2 == nil || modulus == nil {
		return nil, errors.New("nil MultiExpSignedMod input")
	}
	if modulus.Sign() <= 0 {
		return nil, errors.New("invalid MultiExpSignedMod modulus")
	}

	r1, err := ExpSignedMod(base1, exp1, modulus)
	if err != nil {
		return nil, fmt.Errorf("multi-exp first term: %w", err)
	}
	r2, err := ExpSignedMod(base2, exp2, modulus)
	if err != nil {
		return nil, fmt.Errorf("multi-exp second term: %w", err)
	}

	result := new(big.Int).Mul(r1, r2)
	result.Mod(result, modulus)
	return result, nil
}

// ExpSignedModCT computes base^exp mod modulus using constant-time
// exponentiation, handling negative exponents via modular inverse of the base.
// The modulus and exponent must have consistent fixed-width encodings.
//
// To avoid secret-dependent control flow, the modular inverse of the public
// base is always precomputed and the absolute value of the exponent is always
// used. The effective base is selected from {base, invBase} based on the sign
// of exp. This ensures the same sequence of operations regardless of whether
// the exponent is positive or negative.
func ExpSignedModCT(modulus, base *big.Int, exp *secret.SignedInt, modLen, expLen int) (*big.Int, error) {
	if base == nil || exp == nil || modulus == nil {
		return nil, errors.New("nil ExpSignedModCT input")
	}
	if modulus.Sign() <= 0 {
		return nil, errors.New("invalid ExpSignedModCT modulus")
	}
	if expLen <= 0 {
		return nil, errors.New("invalid ExpSignedModCT exponent length")
	}

	// Precompute the modular inverse of the public base unconditionally.
	// base is a public value (e.g., S, T, or a ciphertext), so ModInverse
	// does not leak secret material.
	invBase := new(big.Int).ModInverse(base, modulus)
	if invBase == nil {
		return nil, errors.New("base is not invertible modulo modulus")
	}

	baseBytes := paillierct.FixedEncode(new(big.Int).Mod(base, modulus), modLen)
	inverseBytes := paillierct.FixedEncode(invBase, modLen)
	selectedBase, err := exp.SelectBySign(baseBytes, inverseBytes)
	clear(baseBytes)
	clear(inverseBytes)
	if err != nil {
		return nil, err
	}
	defer clear(selectedBase)
	magnitude := exp.FixedMagnitude()
	defer clear(magnitude)
	if len(magnitude) != expLen {
		return nil, errors.New("secret exponent has invalid width")
	}
	out, err := paillierct.ExpCT(paillierct.FixedEncode(modulus, modLen), selectedBase, magnitude)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(out), nil
}

// validateRPParamsForCommit validates Ring-Pedersen auxiliary parameters for
// use by the modern proof verifiers (Πenc, Πaff-g, Πlog*). It delegates to the
// canonical ValidateRingPedersenParams to ensure consistent validation of:
// non-nil fields, composite odd modulus, unit S/T with fixed-width encoding,
// and non-degenerate values.
func validateRPParamsForCommit(params RingPedersenParams) error {
	return ValidateRingPedersenParams(&params)
}

// --- Ring-Pedersen parameter generation and Πprm proof ---

// GenerateRingPedersenParams creates Ring-Pedersen public parameters tied to
// sk.N and returns the secret lambda needed to prove Πprm.
func GenerateRingPedersenParams(reader io.Reader, sk *pai.PrivateKey) (*RingPedersenParams, *secret.Scalar, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, nil, errors.New("nil Paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, nil, err
	}
	phi, err := paillierPhi(sk)
	if err != nil {
		return nil, nil, err
	}
	defer secret.ClearBigInt(phi)
	nLen := modulusBytes(sk.N)
	var lambda *secret.Scalar
	success := false
	defer func() {
		if !success {
			lambda.Destroy()
		}
	}()
	for {
		v, err := rand.Int(reader, phi)
		if err != nil {
			return nil, nil, err
		}
		if v.Sign() != 0 {
			lambda, err = secretScalarFromBig(v, nLen)
			secret.ClearBigInt(v)
			if err != nil {
				return nil, nil, err
			}
			break
		}
		secret.ClearBigInt(v)
	}
	for {
		t, err := randomCoprime(reader, sk.N)
		if err != nil {
			return nil, nil, err
		}
		if t.Cmp(big.NewInt(1)) <= 0 {
			secret.ClearBigInt(t)
			continue
		}
		s, err := expSecretScalarMod(sk.N, t, lambda, nLen)
		if err != nil {
			secret.ClearBigInt(t)
			return nil, nil, err
		}
		if s.Cmp(big.NewInt(1)) <= 0 {
			secret.ClearBigInt(s)
			secret.ClearBigInt(t)
			continue
		}
		params := &RingPedersenParams{
			N: new(big.Int).Set(sk.N),
			S: s,
			T: t,
		}
		if err := ValidateRingPedersenParams(params); err != nil {
			secret.ClearBigInt(s)
			secret.ClearBigInt(t)
			continue
		}
		success = true
		return params, lambda, nil
	}
}

// ProveRingPedersen creates CGGMP24 Πprm for Ring-Pedersen parameters.
func ProveRingPedersen(reader io.Reader, domain []byte, sk *pai.PrivateKey, params *RingPedersenParams, lambda *secret.Scalar, party uint32) (*RingPedersenProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, errors.New("nil Paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateRingPedersenParams(params); err != nil {
		return nil, err
	}
	if params.N.Cmp(sk.N) != 0 {
		return nil, errors.New("Ring-Pedersen modulus does not match Paillier key")
	}
	if lambda == nil || lambda.FixedLen() != modulusBytes(sk.N) {
		return nil, errors.New("invalid Ring-Pedersen lambda")
	}
	nLen := modulusBytes(sk.N)
	s, err := expSecretScalarMod(sk.N, params.T, lambda, nLen)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(s)
	if s.Cmp(params.S) != 0 {
		return nil, errors.New("Ring-Pedersen lambda does not open s")
	}
	phi, err := paillierPhi(sk)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(phi)
	commitments := make([][]byte, ringPedersenProofRounds)
	nonces := make([]*secret.Scalar, ringPedersenProofRounds)
	defer func() {
		for _, nonce := range nonces {
			nonce.Destroy()
		}
	}()
	for i := range ringPedersenProofRounds {
		nonceBig, err := rand.Int(reader, phi)
		if err != nil {
			return nil, err
		}
		nonce, err := secretScalarFromBig(nonceBig, nLen)
		secret.ClearBigInt(nonceBig)
		if err != nil {
			return nil, err
		}
		commitment, err := expSecretScalarMod(sk.N, params.T, nonce, nLen)
		if err != nil {
			nonce.Destroy()
			return nil, err
		}
		nonces[i] = nonce
		commitments[i] = fixedModNBytes(commitment, nLen)
		secret.ClearBigInt(commitment)
	}
	transcript := ringPedersenTranscript(domain, params, party, commitments)
	challenges := make([]byte, ringPedersenProofRounds)
	responses := make([][]byte, ringPedersenProofRounds)
	lambdaBig, err := secretScalarBig(lambda)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(lambdaBig)
	for i := range ringPedersenProofRounds {
		e := ringPedersenChallenge(transcript, i)
		challenges[i] = e
		z, err := secretScalarBig(nonces[i])
		if err != nil {
			return nil, err
		}
		if e == 1 {
			z.Add(z, lambdaBig)
		}
		z.Mod(z, phi)
		responses[i] = fixedModNBytes(z, nLen)
		secret.ClearBigInt(z)
	}
	return &RingPedersenProof{
		Version:        proofVersion,
		TranscriptHash: transcript,
		Commitments:    commitments,
		Challenges:     challenges,
		Responses:      responses,
	}, nil
}

// VerifyRingPedersen verifies CGGMP24 Πprm for Ring-Pedersen parameters.
func VerifyRingPedersen(domain []byte, params *RingPedersenParams, party uint32, proof *RingPedersenProof) bool {
	if ValidateRingPedersenParams(params) != nil || validateRingPedersenProof(proof) != nil {
		return false
	}
	nLen := modulusBytes(params.N)
	for i := range ringPedersenProofRounds {
		if _, err := decodeFixedUnit("Ring-Pedersen commitment", proof.Commitments[i], params.N, nLen); err != nil {
			return false
		}
		if err := validateFixedResponse("Ring-Pedersen response", proof.Responses[i], params.N, nLen); err != nil {
			return false
		}
		if proof.Challenges[i] != 0 && proof.Challenges[i] != 1 {
			return false
		}
	}
	transcript := ringPedersenTranscript(domain, params, party, proof.Commitments)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	for i := range ringPedersenProofRounds {
		e := ringPedersenChallenge(transcript, i)
		if proof.Challenges[i] != e {
			return false
		}
		commitment := new(big.Int).SetBytes(proof.Commitments[i])
		z := new(big.Int).SetBytes(proof.Responses[i])
		left := new(big.Int).Exp(params.T, z, params.N)
		right := new(big.Int).Set(commitment)
		if e == 1 {
			right.Mul(right, params.S)
			right.Mod(right, params.N)
		}
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

// ValidateRingPedersenParams validates Ring-Pedersen public parameters.
func ValidateRingPedersenParams(params *RingPedersenParams) error {
	if params == nil || params.N == nil || params.S == nil || params.T == nil {
		return errors.New("nil Ring-Pedersen parameters")
	}
	if params.N.Sign() <= 0 || params.N.Bit(0) == 0 || params.N.ProbablyPrime(64) {
		return errors.New("invalid Ring-Pedersen modulus")
	}
	if params.S.Sign() <= 0 || params.S.Cmp(params.N) >= 0 || params.T.Sign() <= 0 || params.T.Cmp(params.N) >= 0 {
		return errors.New("Ring-Pedersen parameter out of range")
	}
	nLen := modulusBytes(params.N)
	if _, err := decodeFixedUnit("Ring-Pedersen s", fixedModNBytes(params.S, nLen), params.N, nLen); err != nil {
		return err
	}
	if _, err := decodeFixedUnit("Ring-Pedersen t", fixedModNBytes(params.T, nLen), params.N, nLen); err != nil {
		return err
	}
	if params.S.Cmp(big.NewInt(1)) <= 0 || params.T.Cmp(big.NewInt(1)) <= 0 {
		return errors.New("degenerate Ring-Pedersen parameters")
	}
	return nil
}

// ringPedersenParamsWire is the wire DTO for RingPedersenParams.
type ringPedersenParamsWire struct {
	N []byte `wire:"1,bytes,max_bits=paillier_modulus_bits"`
	S []byte `wire:"2,bytes,max_bits=paillier_modulus_bits"`
	T []byte `wire:"3,bytes,max_bits=paillier_modulus_bits"`
}

// WireType returns the canonical wire type identifier for ringPedersenParamsWire.
func (ringPedersenParamsWire) WireType() string { return ringPedersenParamsWireType }

// WireVersion returns the wire format version for ringPedersenParamsWire.
func (ringPedersenParamsWire) WireVersion() uint16 { return proofVersion }

// MarshalWireMessage encodes RingPedersenParams as a canonical TLV message.
func (params *RingPedersenParams) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if err := ValidateRingPedersenParams(params); err != nil {
		return nil, err
	}
	nLen := modulusBytes(params.N)
	return wire.Marshal(ringPedersenParamsWire{
		N: fixedModNBytes(params.N, nLen),
		S: fixedModNBytes(params.S, nLen),
		T: fixedModNBytes(params.T, nLen),
	}, opts...)
}

// UnmarshalWireMessage decodes RingPedersenParams from a canonical TLV message.
func (params *RingPedersenParams) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var w ringPedersenParamsWire
	if err := wire.Unmarshal(in, &w, opts...); err != nil {
		return err
	}
	n := new(big.Int).SetBytes(w.N)
	nLen := modulusBytes(n)
	if nLen == 0 || len(w.N) != nLen {
		return errors.New("invalid Ring-Pedersen modulus encoding")
	}
	if len(w.S) != nLen || len(w.T) != nLen {
		return errors.New("invalid Ring-Pedersen parameter width")
	}
	decoded := RingPedersenParams{
		N: n,
		S: new(big.Int).SetBytes(w.S),
		T: new(big.Int).SetBytes(w.T),
	}
	if err := ValidateRingPedersenParams(&decoded); err != nil {
		return err
	}
	*params = decoded
	return nil
}

// MarshalRingPedersenParams encodes Ring-Pedersen parameters canonically.
func MarshalRingPedersenParams(params *RingPedersenParams) ([]byte, error) {
	return wire.Marshal(params, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
	}))
}

// UnmarshalRingPedersenParams decodes Ring-Pedersen parameters.
func UnmarshalRingPedersenParams(in []byte) (*RingPedersenParams, error) {
	params := new(RingPedersenParams)
	if err := params.UnmarshalBinary(in); err != nil {
		return nil, err
	}
	return params, nil
}

// UnmarshalRingPedersenParamsWithMaxModulusBits decodes Ring-Pedersen
// parameters and rejects an oversized modulus before primality checks.
// The modulus size check is enforced by wire.Unmarshal via the
// max_bits=paillier_modulus_bits wire tag on ringPedersenParamsWire.
func UnmarshalRingPedersenParamsWithMaxModulusBits(in []byte, maxBits int) (*RingPedersenParams, error) {
	params := new(RingPedersenParams)
	if err := params.UnmarshalBinaryWithMaxModulusBits(in, maxBits); err != nil {
		return nil, err
	}
	return params, nil
}

// MarshalBinary encodes Ring-Pedersen parameters canonically.
func (params *RingPedersenParams) MarshalBinary() ([]byte, error) {
	return MarshalRingPedersenParams(params)
}

// UnmarshalBinary decodes Ring-Pedersen parameters.
func (params *RingPedersenParams) UnmarshalBinary(in []byte) error {
	return params.UnmarshalBinaryWithMaxModulusBits(in, 0)
}

// UnmarshalBinaryWithMaxModulusBits decodes Ring-Pedersen parameters and
// rejects an oversized modulus before validation.
func (params *RingPedersenParams) UnmarshalBinaryWithMaxModulusBits(in []byte, maxBits int) error {
	if maxBits <= 0 {
		maxBits = tss.DefaultMaxPaillierModulusBits
	}
	return wire.Unmarshal(in, params, wire.WithFieldLimits(wire.FieldLimits{
		"paillier_modulus_bits": maxBits,
	}))
}

// Validate checks Ring-Pedersen parameter structure.
func (params *RingPedersenParams) Validate() error {
	return ValidateRingPedersenParams(params)
}

func marshalRingPedersenProof(p *RingPedersenProof) ([]byte, error) {
	if err := validateRingPedersenProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

// MarshalBinary encodes a Ring-Pedersen proof canonically.
func (p *RingPedersenProof) MarshalBinary() ([]byte, error) {
	return marshalRingPedersenProof(p)
}

// UnmarshalRingPedersenProof decodes and structurally validates Πprm.
func UnmarshalRingPedersenProof(in []byte) (*RingPedersenProof, error) {
	p := new(RingPedersenProof)
	if err := p.UnmarshalBinary(in); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalBinary decodes and structurally validates a Ring-Pedersen proof.
func (p *RingPedersenProof) UnmarshalBinary(in []byte) error {
	var decoded RingPedersenProof
	if err := wire.Unmarshal(in, &decoded); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// AfterUnmarshalWire restores the derived proof version.
func (p *RingPedersenProof) AfterUnmarshalWire() error {
	p.Version = proofVersion
	return nil
}

// Validate checks the Ring-Pedersen proof structure.
func (p *RingPedersenProof) Validate() error {
	return validateRingPedersenProof(p)
}

func validateRingPedersenProof(p *RingPedersenProof) error {
	if p == nil {
		return errors.New("nil Ring-Pedersen proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected Ring-Pedersen proof version %d", p.Version)
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("invalid Ring-Pedersen transcript hash")
	}
	if len(p.Commitments) != ringPedersenProofRounds || len(p.Responses) != ringPedersenProofRounds || len(p.Challenges) != ringPedersenProofRounds {
		return errors.New("invalid Ring-Pedersen proof round count")
	}
	for i := range ringPedersenProofRounds {
		if len(p.Commitments[i]) == 0 || len(p.Responses[i]) == 0 {
			return fmt.Errorf("incomplete Ring-Pedersen proof round %d", i)
		}
		if p.Challenges[i] != 0 && p.Challenges[i] != 1 {
			return fmt.Errorf("invalid Ring-Pedersen challenge bit %d", i)
		}
	}
	return nil
}

func ringPedersenTranscript(domain []byte, params *RingPedersenParams, party uint32, commitments [][]byte) []byte {
	paramsBytes, _ := MarshalRingPedersenParams(params)
	return proofTranscript(ringPedersenProofTag, domain,
		[][]byte{partyBytes(party), paramsBytes},
		[][]byte{wire.EncodeBytesList(commitments)},
	)
}

func ringPedersenChallenge(transcript []byte, round int) byte {
	t := transcriptpkg.New(ringPedersenChallengeLabel)
	t.AppendBytes("transcript_hash", transcript)
	t.AppendUint32("round", uint32(round))
	return t.Sum()[0] & 1
}
