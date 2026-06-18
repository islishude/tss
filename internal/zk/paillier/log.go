package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
)

// ProveLog creates a Π^log proof that ciphertext c = Enc(a, r) and curve point
// A = a·G share the same discrete logarithm a. The proof encodes the point A
// directly rather than requiring a separate scalar commitment, matching the
// CGGMP21 Section 6.2 Π^log structure.
//
// Deprecated: ProveLog is superseded by [ProveLogStar]. New code must use
// [ProveLogStar] which adds Ring-Pedersen hiding for the integer witness. ProveLog
// is retained only for backward compatibility and test vector generation.
//
// Statistical zero-knowledge: α is sampled from [0, 2^{l+ε}) with l=256, ε=128,
// and the challenge e is the full 256-bit hash output, providing ~128 bits of
// statistical hiding for the scalar a.
func ProveLog(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int, pointBytes []byte) (*LogProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if pk == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	if scalar == nil || scalar.Sign() <= 0 || scalar.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("scalar out of range")
	}
	if _, err := secp.PointFromBytes(pointBytes); err != nil {
		return nil, fmt.Errorf("invalid point: %w", err)
	}
	alpha, err := randomLargeMask(reader)
	if err != nil {
		return nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, err
	}
	cipherCommitment, err := pk.EncryptWithRandomness(alpha, rho)
	if err != nil {
		return nil, err
	}
	pointCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(alpha)))
	if err != nil {
		return nil, err
	}
	transcript := logTranscript(domain, pk, ciphertext, pointBytes, cipherCommitment, pointCommitment)
	e := challenge([]byte(logChallengeLabel), transcript)
	z := new(big.Int).Mul(e, scalar)
	z.Add(z, alpha)
	u := new(big.Int).Exp(randomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	return &LogProof{
		Version:          proofVersion,
		Point:            pointBytes,
		CipherCommitment: fixedModN2Bytes(cipherCommitment, pk),
		PointCommitment:  pointCommitment,
		Response:         intBytes(z),
		Randomness:       fixedModNBytes(u, modulusBytes(pk.N)),
		TranscriptHash:   transcript,
	}, nil
}

// VerifyLog checks a Π^log proof that ciphertext c and curve point A share the
// same discrete logarithm. Returns true iff both the Paillier and curve
// verification equations hold.
func VerifyLog(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, proof *LogProof) bool {
	if validateLogProof(proof) != nil || pk == nil || pk.ValidateCiphertext(ciphertext) != nil {
		return false
	}
	point, err := secp.PointFromBytes(proof.Point)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	if err := validateFixedCiphertextBytes("cipher commitment", proof.CipherCommitment, pk); err != nil {
		return false
	}
	pointCommitment, err := secp.PointFromBytes(proof.PointCommitment)
	if err != nil {
		return false
	}
	transcript := logTranscript(domain, pk, ciphertext, proof.Point, cipherCommitment, proof.PointCommitment)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	z := new(big.Int).SetBytes(proof.Response)
	u := new(big.Int).SetBytes(proof.Randomness)
	if z.Sign() <= 0 {
		return false
	}
	if _, err := decodeFixedUnit("log proof randomness", proof.Randomness, pk.N, modulusBytes(pk.N)); err != nil {
		return false
	}
	e := challenge([]byte(logChallengeLabel), transcript)
	// Statistical ZK: z = α + e·a with α ∈ [0, 2^{l+ε}) must satisfy z < 2^{l+ε} + e·q.
	if z.Cmp(zkRangeBound(e)) >= 0 {
		return false
	}
	encZ, err := pk.EncryptWithRandomness(z, u)
	if err != nil {
		return false
	}
	rightCipher := new(big.Int).Exp(ciphertext, e, pk.NSquared)
	rightCipher.Mul(rightCipher, cipherCommitment)
	rightCipher.Mod(rightCipher, pk.NSquared)
	if encZ.Cmp(rightCipher) != 0 {
		return false
	}
	leftPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(z))
	rightPoint := secp.Add(pointCommitment, secp.ScalarMult(point, secp.ScalarFromBigInt(e)))
	return secp.Equal(leftPoint, rightPoint)
}

func validateLogProof(p *LogProof) error {
	if p == nil {
		return errors.New("nil log proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected log proof version %d", p.Version)
	}
	if len(p.Point) == 0 || len(p.CipherCommitment) == 0 || len(p.PointCommitment) == 0 || len(p.Response) == 0 || len(p.Randomness) == 0 || len(p.TranscriptHash) != sha256.Size {
		return errors.New("incomplete log proof")
	}
	if err := validateCurvePointBytes("point", p.Point); err != nil {
		return err
	}
	if err := validateCurvePointBytes("point commitment", p.PointCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	if len(p.CipherCommitment) == 0 || len(p.Randomness) == 0 {
		return errors.New("incomplete fixed-width log proof Paillier field")
	}
	return nil
}

func marshalLogProof(p *LogProof) ([]byte, error) {
	if err := validateLogProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

// MarshalBinary encodes a log proof canonically.
func (p *LogProof) MarshalBinary() ([]byte, error) {
	return marshalLogProof(p)
}

// UnmarshalLogProof decodes and validates a Π^log proof.
func UnmarshalLogProof(in []byte) (*LogProof, error) {
	p := new(LogProof)
	if err := p.UnmarshalBinary(in); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalBinary decodes and validates a log proof.
func (p *LogProof) UnmarshalBinary(in []byte) error {
	var decoded LogProof
	if err := wire.Unmarshal(in, &decoded); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// AfterUnmarshalWire restores the derived proof version.
func (p *LogProof) AfterUnmarshalWire() error {
	p.Version = proofVersion
	return nil
}

// Validate checks the log proof structure.
func (p *LogProof) Validate() error {
	return validateLogProof(p)
}

func logTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, pointBytes []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return proofTranscript(logProofTag, domain,
		[][]byte{pkBytes, fixedModN2Bytes(ciphertext, pk), pointBytes},
		[][]byte{fixedModN2Bytes(cipherCommitment, pk), pointCommitment},
	)
}
