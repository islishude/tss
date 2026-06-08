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

// ProveEncryption creates a unified Π^Enc proof that a Paillier ciphertext
// encrypts a scalar less than the secp256k1 order, and the public curve
// commitment opens to the same scalar. Per CGGMP21 Section 4.1.
//
// Statistical zero-knowledge: α is sampled from [0, 2^{l+ε}) with l=256, ε=128,
// providing ~128 bits of statistical hiding against witness recovery from the
// response z = α + e·m. The challenge e is derived from the full 256-bit hash
// output without modular reduction.
func ProveEncryption(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int) (*EncryptionProof, error) {
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
	scalarCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
	if err != nil {
		return nil, err
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
	bound := secp.Order().Bytes()
	transcript := encryptionTranscript(domain, pk, ciphertext, scalarCommitment, bound, cipherCommitment, pointCommitment)
	e := challenge([]byte(encryptionChallengeLabel), transcript)
	z := new(big.Int).Mul(e, scalar)
	z.Add(z, alpha)
	u := new(big.Int).Exp(randomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	return &EncryptionProof{
		Version:          proofVersion,
		ScalarCommitment: scalarCommitment,
		CipherCommitment: fixedModN2Bytes(cipherCommitment, pk),
		PointCommitment:  pointCommitment,
		Bound:            bound,
		Response:         intBytes(z),
		Randomness:       fixedModNBytes(u, modulusBytes(pk.N)),
		TranscriptHash:   transcript,
	}, nil
}

// VerifyEncryption checks the unified Π^Enc proof against a ciphertext and public key.
func VerifyEncryption(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, proof *EncryptionProof) bool {
	if validateEncryptionProof(proof) != nil || pk == nil || pk.ValidateCiphertext(ciphertext) != nil {
		return false
	}
	if new(big.Int).SetBytes(proof.Bound).Cmp(secp.Order()) != 0 {
		return false
	}
	scalarCommitment, err := secp.PointFromBytes(proof.ScalarCommitment)
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
	transcript := encryptionTranscript(domain, pk, ciphertext, proof.ScalarCommitment, proof.Bound, cipherCommitment, proof.PointCommitment)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	z := new(big.Int).SetBytes(proof.Response)
	u := new(big.Int).SetBytes(proof.Randomness)
	if z.Sign() <= 0 {
		return false
	}
	if _, err := decodeFixedUnit("encryption proof randomness", proof.Randomness, pk.N, modulusBytes(pk.N)); err != nil {
		return false
	}
	e := challenge([]byte(encryptionChallengeLabel), transcript)
	// Statistical ZK: z = α + e·m with α ∈ [0, 2^{l+ε}) must satisfy z < 2^{l+ε} + e·q.
	if z.Cmp(zkRangeBound(e)) >= 0 {
		return false
	}
	// Paillier check: Enc(z, u) == cipherCommitment * ciphertext^e (mod N^2).
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
	// Curve check: z*G == pointCommitment + e * scalarCommitment.
	leftPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(z))
	rightPoint := secp.Add(pointCommitment, secp.ScalarMult(scalarCommitment, secp.ScalarFromBigInt(e)))
	return secp.Equal(leftPoint, rightPoint)
}

func validateEncryptionProof(p *EncryptionProof) error {
	if p == nil {
		return errors.New("nil encryption proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected encryption proof version %d", p.Version)
	}
	if len(p.ScalarCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.PointCommitment) == 0 || len(p.Bound) == 0 || len(p.Response) == 0 || len(p.Randomness) == 0 || len(p.TranscriptHash) != sha256.Size {
		return errors.New("incomplete encryption proof")
	}
	if err := validateCurvePointBytes("scalar commitment", p.ScalarCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("point commitment", p.PointCommitment); err != nil {
		return err
	}
	if len(p.CipherCommitment) == 0 {
		return errors.New("cipher commitment is empty")
	}
	if len(p.Randomness) == 0 {
		return errors.New("randomness is empty")
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("bound", p.Bound); err != nil {
		return err
	}
	return nil
}

func marshalEncryptionProof(p *EncryptionProof) ([]byte, error) {
	if err := validateEncryptionProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, encryptionProofWireType, []wire.Field{
		{Tag: encryptionProofFieldScalarCommitment, Value: wire.NonNilBytes(p.ScalarCommitment)},
		{Tag: encryptionProofFieldCipherCommitment, Value: wire.NonNilBytes(p.CipherCommitment)},
		{Tag: encryptionProofFieldPointCommitment, Value: wire.NonNilBytes(p.PointCommitment)},
		{Tag: encryptionProofFieldBound, Value: wire.NonNilBytes(p.Bound)},
		{Tag: encryptionProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
		{Tag: encryptionProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
		{Tag: encryptionProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
	})
}

// UnmarshalEncryptionProof decodes and validates an encryption proof.
func UnmarshalEncryptionProof(in []byte) (*EncryptionProof, error) {
	version, fields, err := wire.Unmarshal(in, encryptionProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected encryption proof version %d", version)
	}
	if err := requireExactProofTags(fields, encryptionProofFieldScalarCommitment, encryptionProofFieldCipherCommitment, encryptionProofFieldPointCommitment, encryptionProofFieldBound, encryptionProofFieldResponse, encryptionProofFieldRandomness, encryptionProofFieldTranscriptHash); err != nil {
		return nil, err
	}
	p := &EncryptionProof{
		Version:          proofVersion,
		ScalarCommitment: wire.MustField(fields, encryptionProofFieldScalarCommitment),
		CipherCommitment: wire.MustField(fields, encryptionProofFieldCipherCommitment),
		PointCommitment:  wire.MustField(fields, encryptionProofFieldPointCommitment),
		Bound:            wire.MustField(fields, encryptionProofFieldBound),
		Response:         wire.MustField(fields, encryptionProofFieldResponse),
		Randomness:       wire.MustField(fields, encryptionProofFieldRandomness),
		TranscriptHash:   wire.MustField(fields, encryptionProofFieldTranscriptHash),
	}
	if err := validateEncryptionProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

func encryptionTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, scalarCommitment, bound []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return proofTranscript(encryptionProofTag, domain,
		[][]byte{pkBytes, fixedModN2Bytes(ciphertext, pk), scalarCommitment, fixedScalarBytes(new(big.Int).SetBytes(bound))},
		[][]byte{fixedModN2Bytes(cipherCommitment, pk), pointCommitment},
	)
}
