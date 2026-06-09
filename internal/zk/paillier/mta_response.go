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
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/wire"
)

// ProveMTAResponse proves response encrypts a*b+beta for committed b.
//
// Statistical zero-knowledge: μ and ν are sampled from [0, 2^{l+ε}) with
// l=256, ε=128, and the challenge e is the full 256-bit hash output. This
// provides ~128 bits of statistical hiding for both b (via zB = e·b + μ)
// and beta (via zBeta = e·beta + ν).
func ProveMTAResponse(reader io.Reader, domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment []byte, b, beta, betaRandomness *big.Int) (*MTAResponseProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if pk == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(encA); err != nil {
		return nil, fmt.Errorf("invalid input ciphertext: %w", err)
	}
	if err := pk.ValidateCiphertext(response); err != nil {
		return nil, fmt.Errorf("invalid response ciphertext: %w", err)
	}
	if b == nil || b.Sign() <= 0 || b.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("b out of range")
	}
	if beta == nil {
		return nil, errors.New("nil beta")
	}
	betaMod := mod(beta, secp.Order())
	expectedBCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bCommitment, expectedBCommit) {
		return nil, errors.New("b commitment mismatch")
	}
	betaCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(betaMod)))
	if err != nil {
		return nil, err
	}
	mu, err := randomLargeMask(reader)
	if err != nil {
		return nil, err
	}
	nu, err := randomLargeMask(reader)
	if err != nil {
		return nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, err
	}
	encNu, err := pk.EncryptWithRandomness(nu, rho)
	if err != nil {
		return nil, err
	}
	// encA^mu uses a proof nonce that is later masked into zB = e*b + mu.
	// Keep this exponentiation constant-time so timing leakage of mu cannot
	// recover the MtA responder scalar b from the public response.
	nLen := (pk.N.BitLen() + 7) / 8
	nSquaredLen := 2 * nLen
	nSquaredBytes := paillierct.FixedEncode(pk.NSquared, nSquaredLen)
	encABytes := paillierct.FixedEncode(encA, nSquaredLen)
	muFixed := paillierct.FixedEncode(mu, nSquaredLen)
	encAMuBytes, err := paillierct.ExpCT(nSquaredBytes, encABytes, muFixed)
	if err != nil {
		return nil, err
	}
	cipherCommitment := new(big.Int).SetBytes(encAMuBytes)
	cipherCommitment.Mul(cipherCommitment, encNu)
	cipherCommitment.Mod(cipherCommitment, pk.NSquared)
	bNonce, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(mu)))
	if err != nil {
		return nil, err
	}
	betaNonce, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(nu)))
	if err != nil {
		return nil, err
	}
	transcript := mtaTranscript(domain, pk, encA, response, expectedBCommit, betaCommitment, cipherCommitment, bNonce, betaNonce)
	e := challenge([]byte(mtaChallengeLabel), transcript)
	zB := new(big.Int).Mul(e, b)
	zB.Add(zB, mu)
	zBeta := new(big.Int).Mul(e, betaMod)
	zBeta.Add(zBeta, nu)
	u := new(big.Int).Exp(betaRandomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	return &MTAResponseProof{
		Version:          proofVersion,
		TranscriptHash:   transcript,
		BetaCommitment:   betaCommitment,
		CipherCommitment: fixedModN2Bytes(cipherCommitment, pk),
		BCommitment:      bNonce,
		BetaNonce:        betaNonce,
		BResponse:        intBytes(zB),
		BetaResponse:     intBytes(zBeta),
		Randomness:       fixedModNBytes(u, nLen),
	}, nil
}

// VerifyMTAResponse checks the MtA response proof and transcript binding.
func VerifyMTAResponse(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitmentBytes []byte, proof *MTAResponseProof) bool {
	if validateMTAResponseProof(proof) != nil || pk == nil || pk.ValidateCiphertext(encA) != nil || pk.ValidateCiphertext(response) != nil {
		return false
	}
	if err := validateMTAResponseProofBounds(proof, pk); err != nil {
		return false
	}
	bCommitment, err := secp.PointFromBytes(bCommitmentBytes)
	if err != nil {
		return false
	}
	betaCommitment, err := secp.PointFromBytes(proof.BetaCommitment)
	if err != nil {
		return false
	}
	bNonce, err := secp.PointFromBytes(proof.BCommitment)
	if err != nil {
		return false
	}
	betaNonce, err := secp.PointFromBytes(proof.BetaNonce)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	if err := validateFixedCiphertextBytes("cipher commitment", proof.CipherCommitment, pk); err != nil {
		return false
	}
	zB := new(big.Int).SetBytes(proof.BResponse)
	zBeta := new(big.Int).SetBytes(proof.BetaResponse)
	u := new(big.Int).SetBytes(proof.Randomness)
	if zB.Sign() <= 0 || zBeta.Sign() <= 0 {
		return false
	}
	if _, err := decodeFixedUnit("MtA randomness", proof.Randomness, pk.N, modulusBytes(pk.N)); err != nil {
		return false
	}
	transcript := mtaTranscript(domain, pk, encA, response, bCommitmentBytes, proof.BetaCommitment, cipherCommitment, proof.BCommitment, proof.BetaNonce)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	e := challenge([]byte(mtaChallengeLabel), transcript)

	maxResponse := zkRangeBound(e)
	// Statistical ZK: zB = e·b + μ and zBeta = e·beta + ν each satisfy the same bound.
	if zB.Cmp(maxResponse) >= 0 || zBeta.Cmp(maxResponse) >= 0 {
		return false
	}

	encZBeta, err := pk.EncryptWithRandomness(zBeta, u)
	if err != nil {
		return false
	}
	leftCipher := new(big.Int).Exp(encA, zB, pk.NSquared)
	leftCipher.Mul(leftCipher, encZBeta)
	leftCipher.Mod(leftCipher, pk.NSquared)
	rightCipher := new(big.Int).Exp(response, e, pk.NSquared)
	rightCipher.Mul(rightCipher, cipherCommitment)
	rightCipher.Mod(rightCipher, pk.NSquared)
	if leftCipher.Cmp(rightCipher) != 0 {
		return false
	}
	leftB := secp.ScalarBaseMult(secp.ScalarFromBigInt(zB))
	rightB := secp.Add(bNonce, secp.ScalarMult(bCommitment, secp.ScalarFromBigInt(e)))
	if !secp.Equal(leftB, rightB) {
		return false
	}
	leftBeta := secp.ScalarBaseMult(secp.ScalarFromBigInt(zBeta))
	rightBeta := secp.Add(betaNonce, secp.ScalarMult(betaCommitment, secp.ScalarFromBigInt(e)))
	return secp.Equal(leftBeta, rightBeta)
}

func validateMTAResponseProof(p *MTAResponseProof) error {
	if p == nil {
		return errors.New("nil MtA response proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected MtA response proof version %d", p.Version)
	}
	if len(p.TranscriptHash) != sha256.Size || len(p.BetaCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.BCommitment) == 0 || len(p.BetaNonce) == 0 || len(p.BResponse) == 0 || len(p.BetaResponse) == 0 || len(p.Randomness) == 0 {
		return errors.New("incomplete MtA response proof")
	}
	if err := validateCurvePointBytes("beta commitment", p.BetaCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("b commitment", p.BCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("beta nonce", p.BetaNonce); err != nil {
		return err
	}
	// Cipher commitments and randomizers are fixed-width Paillier integers;
	// leading zero bytes are canonical padding, not alternate encodings.
	if len(p.BResponse) > mtaResponseScalarMaxBytes {
		return errors.New("MtA b response too large")
	}
	if err := validatePositiveIntBytes("b response", p.BResponse); err != nil {
		return err
	}
	if len(p.BetaResponse) > mtaResponseScalarMaxBytes {
		return errors.New("MtA beta response too large")
	}
	if err := validatePositiveIntBytes("beta response", p.BetaResponse); err != nil {
		return err
	}
	if len(p.CipherCommitment) == 0 || len(p.Randomness) == 0 {
		return errors.New("incomplete fixed-width MtA Paillier field")
	}
	return nil
}

func validateMTAResponseProofBounds(p *MTAResponseProof, pk *pai.PublicKey) error {
	if pk == nil || pk.N == nil {
		return errors.New("nil Paillier public key")
	}
	nLen := (pk.N.BitLen() + 7) / 8
	nSquaredLen := 2 * nLen
	if len(p.CipherCommitment) != nSquaredLen {
		return errors.New("MtA cipher commitment has invalid width")
	}
	if len(p.Randomness) != nLen {
		return errors.New("MtA randomness has invalid width")
	}
	if len(p.BResponse) > mtaResponseScalarMaxBytes {
		return errors.New("MtA b response too large")
	}
	if len(p.BetaResponse) > mtaResponseScalarMaxBytes {
		return errors.New("MtA beta response too large")
	}
	return nil
}

func marshalMTAResponseProof(p *MTAResponseProof) ([]byte, error) {
	if err := validateMTAResponseProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

// UnmarshalMTAResponseProof decodes and validates an MtA response proof shell.
func UnmarshalMTAResponseProof(in []byte) (*MTAResponseProof, error) {
	var p MTAResponseProof
	if err := wire.Unmarshal(in, &p); err != nil {
		return nil, err
	}
	p.Version = proofVersion
	if err := validateMTAResponseProof(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func mtaTranscript(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment, betaCommitment []byte, cipherCommitment *big.Int, bNonce, betaNonce []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return proofTranscript(mtaProofTag, domain,
		[][]byte{pkBytes, fixedModN2Bytes(encA, pk), fixedModN2Bytes(response, pk), bCommitment, betaCommitment},
		[][]byte{fixedModN2Bytes(cipherCommitment, pk), bNonce, betaNonce},
	)
}
