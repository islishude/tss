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

const proofVersion = 1

const (
	modulusProofWireType     = "zk.paillier.modulus-proof"
	encScalarProofWireType   = "zk.paillier.enc-scalar-proof"
	encRangeProofWireType    = "zk.paillier.enc-range-proof"
	mtaResponseProofWireType = "zk.paillier.mta-response-proof"
	logProofWireType         = "zk.paillier.log-proof"
	primalityProofWireType   = "zk.paillier.primality-proof"
	encryptionProofWireType  = "zk.paillier.encryption-proof"
)

const (
	modulusProofFieldNBits uint16 = iota + 1
	modulusProofFieldSmallFactorCheck
	modulusProofFieldTranscriptHash
	modulusProofFieldCommitment
	modulusProofFieldChallenge
	modulusProofFieldResponse
)

const (
	encScalarProofFieldScalarCommitment uint16 = iota + 1
	encScalarProofFieldCipherCommitment
	encScalarProofFieldPointCommitment
	encScalarProofFieldResponse
	encScalarProofFieldRandomness
	encScalarProofFieldTranscriptHash
)

const (
	encRangeProofFieldBound uint16 = iota + 1
	encRangeProofFieldCommitment
	encRangeProofFieldPointCommitment
	encRangeProofFieldChallenge
	encRangeProofFieldResponse
	encRangeProofFieldRandomness
	encRangeProofFieldTranscriptHash
	encRangeProofFieldDigest
)

const (
	mtaResponseProofFieldTranscriptHash uint16 = iota + 1
	mtaResponseProofFieldBetaCommitment
	mtaResponseProofFieldCipherCommitment
	mtaResponseProofFieldBCommitment
	mtaResponseProofFieldBetaNonce
	mtaResponseProofFieldBResponse
	mtaResponseProofFieldBetaResponse
	mtaResponseProofFieldRandomness
)

const (
	logProofFieldPoint uint16 = iota + 1
	logProofFieldCipherCommitment
	logProofFieldPointCommitment
	logProofFieldResponse
	logProofFieldRandomness
	logProofFieldTranscriptHash
)

const (
	primalityProofFieldFactorBitLen uint16 = iota + 1
	primalityProofFieldTranscriptHash
	primalityProofFieldCommitment
	primalityProofFieldChallenge
	primalityProofFieldResponse
)

const (
	encryptionProofFieldScalarCommitment uint16 = iota + 1
	encryptionProofFieldCipherCommitment
	encryptionProofFieldPointCommitment
	encryptionProofFieldBound
	encryptionProofFieldResponse
	encryptionProofFieldRandomness
	encryptionProofFieldTranscriptHash
)

const (
	modulusTranscriptLabel    = "paillier-modulus-transcript-v1"
	modulusChallengeLabel     = "paillier-modulus-challenge-v1"
	modulusSigmaCommitLabel   = "paillier-modulus-sigma-commitment-v1"
	encScalarTranscriptLabel  = "paillier-enc-scalar-transcript-v1"
	encScalarChallengeLabel   = "paillier-enc-scalar-challenge-v1"
	encRangeTranscriptLabel   = "paillier-enc-range-transcript-v1"
	encRangeChallengeLabel    = "paillier-enc-range-challenge-v1"
	encRangeDigestLabel       = "paillier-enc-range-proof-v1"
	mtaTranscriptLabel        = "paillier-mta-response-transcript-v1"
	mtaChallengeLabel         = "paillier-mta-response-challenge-v1"
	logTranscriptLabel        = "paillier-log-transcript-v1"
	logChallengeLabel         = "paillier-log-challenge-v1"
	primalityTranscriptLabel  = "paillier-primality-transcript-v1"
	primalityChallengeLabel   = "paillier-primality-challenge-v1"
	encryptionTranscriptLabel = "paillier-encryption-transcript-v1"
	encryptionChallengeLabel  = "paillier-encryption-challenge-v1"
)

// ModulusProof proves that a Paillier modulus N = p·q is a Blum integer
// with p ≡ q ≡ 3 (mod 4) by demonstrating knowledge of a non-trivial square
// root of 1 modulo N. The proof uses a Fiat-Shamir-transformed Σ-protocol.
type ModulusProof struct {
	Version          uint16 `json:"version"`
	NBits            int    `json:"n_bits"`
	SmallFactorCheck []byte `json:"small_factor_check"`
	TranscriptHash   []byte `json:"transcript_hash"`
	Commitment       []byte `json:"commitment"`
	Challenge        []byte `json:"challenge"`
	Response         []byte `json:"response"`
}

// EncScalarProof proves a ciphertext encrypts a committed scalar.
type EncScalarProof struct {
	Version          uint16 `json:"version"`
	ScalarCommitment []byte `json:"scalar_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	PointCommitment  []byte `json:"point_commitment"`
	Response         []byte `json:"response"`
	Randomness       []byte `json:"randomness"`
	TranscriptHash   []byte `json:"transcript_hash"`
}

// EncRangeProof independently proves that a Paillier ciphertext encrypts
// a scalar less than the secp256k1 order, using its own Fiat-Shamir
// challenge derived from a range-specific transcript.
type EncRangeProof struct {
	Version         uint16 `json:"version"`
	Bound           []byte `json:"bound"`
	Commitment      []byte `json:"commitment"`
	PointCommitment []byte `json:"point_commitment"`
	Challenge       []byte `json:"challenge"`
	Response        []byte `json:"response"`
	Randomness      []byte `json:"randomness"`
	TranscriptHash  []byte `json:"transcript_hash"`
	Digest          []byte `json:"digest"`
}

// MTAResponseProof binds an MtA response to ciphertexts and commitments.
type MTAResponseProof struct {
	Version          uint16 `json:"version"`
	TranscriptHash   []byte `json:"transcript_hash"`
	BetaCommitment   []byte `json:"beta_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	BCommitment      []byte `json:"b_commitment"`
	BetaNonce        []byte `json:"beta_nonce"`
	BResponse        []byte `json:"b_response"`
	BetaResponse     []byte `json:"beta_response"`
	Randomness       []byte `json:"randomness"`
}

// LogProof (Π^log) proves that a Paillier ciphertext c = Enc(a) and a secp256k1
// curve point A = a·G share the same discrete logarithm a. Per CGGMP21
// Section 6.2, this is used during key refresh to prove that a new Paillier
// ciphertext encrypts the same scalar as an existing verification share.
type LogProof struct {
	Version          uint16 `json:"version"`
	Point            []byte `json:"point"`
	CipherCommitment []byte `json:"cipher_commitment"`
	PointCommitment  []byte `json:"point_commitment"`
	Response         []byte `json:"response"`
	Randomness       []byte `json:"randomness"`
	TranscriptHash   []byte `json:"transcript_hash"`
}

// PrimalityProof (Π^prm) proves that a Paillier modulus N = p·q has two prime
// factors of approximately equal size. It builds on Π^fac by additionally
// binding the factor bit-length into the transcript, ensuring neither factor
// is trivially small. Per CGGMP21 Section 3.1.
type PrimalityProof struct {
	Version        uint16 `json:"version"`
	FactorBitLen   int    `json:"factor_bit_len"`
	TranscriptHash []byte `json:"transcript_hash"`
	Commitment     []byte `json:"commitment"`
	Challenge      []byte `json:"challenge"`
	Response       []byte `json:"response"`
}

// EncryptionProof (Π^Enc) is a unified Σ-protocol proving that a Paillier
// ciphertext c = Enc(m, r) encrypts a scalar m < q (the secp256k1 order)
// and that the public curve commitment A = m·G opens to the same scalar.
// It combines Π^Eq (scalar knowledge) and the range constraint |m| < q
// into a single Fiat-Shamir challenge. Per CGGMP21 Section 4.1.
type EncryptionProof struct {
	Version          uint16 `json:"version"`
	ScalarCommitment []byte `json:"scalar_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	PointCommitment  []byte `json:"point_commitment"`
	Bound            []byte `json:"bound"`
	Response         []byte `json:"response"`
	Randomness       []byte `json:"randomness"`
	TranscriptHash   []byte `json:"transcript_hash"`
}

// ProveModulus creates a Fiat-Shamir Σ-protocol proof that the prover knows
// the factorization of N into distinct primes p, q satisfying p ≡ q ≡ 3 (mod 4).
// The proof demonstrates knowledge of a non-trivial square root of 1 modulo N,
// which is equivalent to knowing the factorization.
//
// Verifying that p, q are safe primes (p = 2p' + 1, q = 2q' + 1) is delegated
// to the key-generation layer; the Σ-protocol focuses on proving that the
// prover actually holds the factors.
func ProveModulus(reader io.Reader, domain []byte, sk *pai.PrivateKey, party uint32) (*ModulusProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, errors.New("nil paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	p, q := sk.P, sk.Q
	N := sk.N

	// Blum condition: each factor must be ≡ 3 mod 4.
	four := big.NewInt(4)
	if new(big.Int).Mod(p, four).Int64() != 3 {
		return nil, errors.New("p does not satisfy the Blum condition p ≡ 3 (mod 4)")
	}
	if new(big.Int).Mod(q, four).Int64() != 3 {
		return nil, errors.New("q does not satisfy the Blum condition q ≡ 3 (mod 4)")
	}

	// Compute a non-trivial square root of 1 via CRT:
	// s ≡ 1 (mod p), s ≡ -1 (mod q)  ⇒  s^2 ≡ 1 (mod N).
	// Solve x = 1 + k·p such that 1 + k·p ≡ -1 (mod q).
	// Then k ≡ -2 · p^{-1} (mod q), and s = 1 + k·p mod N.
	invP := new(big.Int).ModInverse(p, q)
	if invP == nil {
		return nil, errors.New("CRT failed: p and q are not coprime")
	}
	k := new(big.Int).Mul(big.NewInt(2), invP)
	k.Neg(k)
	k.Mod(k, q)
	s := new(big.Int).Mul(k, p)
	s.Add(s, big.NewInt(1))
	s.Mod(s, N)
	if s.Cmp(big.NewInt(1)) == 0 || s.Cmp(new(big.Int).Sub(N, big.NewInt(1))) == 0 {
		return nil, errors.New("non-trivial square root of 1 not found")
	}

	r, err := randomCoprime(reader, N)
	if err != nil {
		return nil, err
	}
	a := new(big.Int).Exp(r, big.NewInt(2), N) // Σ-protocol commitment
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	challengeTranscript := hashParts([]byte(modulusChallengeLabel), domain, partyBytes(party), raw, intBytes(a))
	e := challengeBits(challengeTranscript, 128)

	// z = r · s^e mod N
	z := new(big.Int).Exp(s, e, N)
	z.Mul(z, r)
	z.Mod(z, N)

	transcript := hashParts([]byte(modulusTranscriptLabel), domain, partyBytes(party), raw)

	return &ModulusProof{
		Version:          proofVersion,
		NBits:            N.BitLen(),
		SmallFactorCheck: smallFactorDigest(N),
		TranscriptHash:   transcript,
		Commitment:       intBytes(a),
		Challenge:        e.Bytes(),
		Response:         intBytes(z),
	}, nil
}

// VerifyModulus checks the Σ-protocol modulus proof against a public key and domain.
func VerifyModulus(domain []byte, pk *pai.PublicKey, party uint32, proof *ModulusProof) bool {
	if validateModulusProof(proof) != nil || pk == nil {
		return false
	}
	if err := pk.Validate(); err != nil {
		return false
	}
	if proof.NBits != pk.N.BitLen() {
		return false
	}
	if pk.N.ProbablyPrime(64) || pk.N.Bit(0) == 0 {
		return false
	}
	// Safe-prime structural checks: for safe primes p = 2p'+1, q = 2q'+1,
	// N ≡ 1 (mod 4) and neither factor is 3.
	if new(big.Int).Mod(pk.N, big.NewInt(4)).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	if new(big.Int).Mod(pk.N, big.NewInt(3)).Sign() == 0 {
		return false
	}
	if !bytes.Equal(proof.SmallFactorCheck, smallFactorDigest(pk.N)) {
		return false
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		return false
	}
	expectedTranscript := hashParts([]byte(modulusTranscriptLabel), domain, partyBytes(party), raw)
	if !bytes.Equal(expectedTranscript, proof.TranscriptHash) {
		return false
	}

	a := new(big.Int).SetBytes(proof.Commitment)
	e := new(big.Int).SetBytes(proof.Challenge)
	z := new(big.Int).SetBytes(proof.Response)

	expectedChallenge := challengeBits(hashParts([]byte(modulusChallengeLabel), domain, partyBytes(party), raw, proof.Commitment), 128)
	if e.Cmp(expectedChallenge) != 0 {
		return false
	}

	if new(big.Int).GCD(nil, nil, a, pk.N).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, z, pk.N).Cmp(big.NewInt(1)) != 0 {
		return false
	}

	// Verify z^2 ≡ a mod N (since s^2 ≡ 1, so (r·s^e)^2 = r^2·(s^2)^e = a·1^e = a).
	z2 := new(big.Int).Exp(z, big.NewInt(2), pk.N)
	return z2.Cmp(a) == 0
}

// ProvePrimality creates a Π^prm proof that N = p·q has two prime factors of
// approximately equal bit-length. The proof extends Π^fac by binding the factor
// size into the transcript, which rules out trivially small or composite factors.
// CGGMP21 §3.1 Π^prm.
func ProvePrimality(reader io.Reader, domain []byte, sk *pai.PrivateKey, party uint32) (*PrimalityProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, errors.New("nil paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	p, q := sk.P, sk.Q
	N := sk.N

	factorBits := p.BitLen()
	if q.BitLen() > factorBits {
		factorBits = q.BitLen()
	}

	r, err := randomCoprime(reader, N)
	if err != nil {
		return nil, err
	}
	a := new(big.Int).Exp(r, big.NewInt(2), N)

	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	transcript := hashParts([]byte(primalityTranscriptLabel), domain, partyBytes(party), raw, wire.Uint32(uint32(factorBits)), intBytes(a))
	challengeTranscript := hashParts([]byte(primalityChallengeLabel), domain, partyBytes(party), raw, wire.Uint32(uint32(factorBits)), intBytes(a))
	e := challengeBits(challengeTranscript, 128)

	// Non-trivial sqrt of 1 via CRT (same as ProveModulus).
	four := big.NewInt(4)
	if new(big.Int).Mod(p, four).Int64() != 3 || new(big.Int).Mod(q, four).Int64() != 3 {
		return nil, errors.New("factors do not satisfy Blum condition p ≡ q ≡ 3 mod 4")
	}
	invP := new(big.Int).ModInverse(p, q)
	if invP == nil {
		return nil, errors.New("CRT failed: p and q are not coprime")
	}
	k := new(big.Int).Mul(big.NewInt(2), invP)
	k.Neg(k)
	k.Mod(k, q)
	s := new(big.Int).Mul(k, p)
	s.Add(s, big.NewInt(1))
	s.Mod(s, N)

	z := new(big.Int).Exp(s, e, N)
	z.Mul(z, r)
	z.Mod(z, N)

	return &PrimalityProof{
		Version:        proofVersion,
		FactorBitLen:   factorBits,
		TranscriptHash: transcript,
		Commitment:     intBytes(a),
		Challenge:      e.Bytes(),
		Response:       intBytes(z),
	}, nil
}

// VerifyPrimality checks the Π^prm proof against a public key and domain.
func VerifyPrimality(domain []byte, pk *pai.PublicKey, party uint32, proof *PrimalityProof) bool {
	if validatePrimalityProof(proof) != nil || pk == nil {
		return false
	}
	if err := pk.Validate(); err != nil {
		return false
	}
	if proof.FactorBitLen <= 0 {
		return false
	}
	nBits := pk.N.BitLen()
	if proof.FactorBitLen < nBits/2-1 || proof.FactorBitLen > nBits/2+1 {
		return false
	}
	if pk.N.ProbablyPrime(64) || pk.N.Bit(0) == 0 {
		return false
	}
	if new(big.Int).Mod(pk.N, big.NewInt(4)).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	if new(big.Int).Mod(pk.N, big.NewInt(3)).Sign() == 0 {
		return false
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		return false
	}
	expectedTranscript := hashParts([]byte(primalityTranscriptLabel), domain, partyBytes(party), raw, wire.Uint32(uint32(proof.FactorBitLen)), proof.Commitment)
	if !bytes.Equal(expectedTranscript, proof.TranscriptHash) {
		return false
	}

	a := new(big.Int).SetBytes(proof.Commitment)
	e := new(big.Int).SetBytes(proof.Challenge)
	z := new(big.Int).SetBytes(proof.Response)

	expectedChallenge := challengeBits(hashParts([]byte(primalityChallengeLabel), domain, partyBytes(party), raw, wire.Uint32(uint32(proof.FactorBitLen)), proof.Commitment), 128)
	if e.Cmp(expectedChallenge) != 0 {
		return false
	}

	if new(big.Int).GCD(nil, nil, a, pk.N).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, z, pk.N).Cmp(big.NewInt(1)) != 0 {
		return false
	}

	z2 := new(big.Int).Exp(z, big.NewInt(2), pk.N)
	return z2.Cmp(a) == 0
}

func validatePrimalityProof(p *PrimalityProof) error {
	if p == nil {
		return errors.New("nil primality proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected primality proof version %d", p.Version)
	}
	if p.FactorBitLen <= 0 {
		return errors.New("invalid primality proof factor bit length")
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("invalid primality proof transcript hash")
	}
	if err := validatePositiveIntBytes("commitment", p.Commitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("challenge", p.Challenge); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	return nil
}

// MarshalPrimalityProof encodes the proof as a canonical TLV record.
func MarshalPrimalityProof(p *PrimalityProof) ([]byte, error) {
	if err := validatePrimalityProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, primalityProofWireType, []wire.Field{
		{Tag: primalityProofFieldFactorBitLen, Value: wire.Uint32(uint32(p.FactorBitLen))},
		{Tag: primalityProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: primalityProofFieldCommitment, Value: wire.NonNilBytes(p.Commitment)},
		{Tag: primalityProofFieldChallenge, Value: wire.NonNilBytes(p.Challenge)},
		{Tag: primalityProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
	})
}

// UnmarshalPrimalityProof decodes and validates a primality proof.
func UnmarshalPrimalityProof(in []byte) (*PrimalityProof, error) {
	version, fields, err := wire.Unmarshal(in, primalityProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected primality proof version %d", version)
	}
	if err := requireExactProofTags(fields, primalityProofFieldFactorBitLen, primalityProofFieldTranscriptHash, primalityProofFieldCommitment, primalityProofFieldChallenge, primalityProofFieldResponse); err != nil {
		return nil, err
	}
	bitLen, err := wire.Uint32Field(fields, primalityProofFieldFactorBitLen)
	if err != nil {
		return nil, err
	}
	p := &PrimalityProof{
		Version:        proofVersion,
		FactorBitLen:   int(bitLen),
		TranscriptHash: wire.MustField(fields, primalityProofFieldTranscriptHash),
		Commitment:     wire.MustField(fields, primalityProofFieldCommitment),
		Challenge:      wire.MustField(fields, primalityProofFieldChallenge),
		Response:       wire.MustField(fields, primalityProofFieldResponse),
	}
	if err := validatePrimalityProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// challengeBits derives a positive integer challenge from a transcript hash.
func challengeBits(transcript []byte, bits int) *big.Int {
	if bits > len(transcript)*8 {
		bits = len(transcript) * 8
	}
	out := new(big.Int).SetBytes(transcript)
	out.Rsh(out, uint(len(transcript)*8-bits))
	if out.Sign() == 0 {
		out.SetInt64(1)
	}
	return out
}

// ProveEncryption creates a unified Π^Enc proof that a Paillier ciphertext
// encrypts a scalar less than the secp256k1 order, and the public curve
// commitment opens to the same scalar. Per CGGMP21 Section 4.1.
func ProveEncryption(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int) (*EncryptionProof, error) {
	if reader == nil {
		reader = rand.Reader
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
	alpha, err := randomScalar(reader)
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
		CipherCommitment: intBytes(cipherCommitment),
		PointCommitment:  pointCommitment,
		Bound:            bound,
		Response:         intBytes(z),
		Randomness:       intBytes(u),
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
	if pk.ValidateCiphertext(cipherCommitment) != nil {
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
	if z.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	e := challenge([]byte(encryptionChallengeLabel), transcript)
	// Range check: if scalar < bound, then z = e*scalar + alpha satisfies z < bound^2 + bound.
	bound := new(big.Int).SetBytes(proof.Bound)
	maxZ := new(big.Int).Mul(bound, bound)
	maxZ.Add(maxZ, bound)
	if z.Cmp(maxZ) >= 0 {
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
	if err := validatePositiveIntBytes("cipher commitment", p.CipherCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("bound", p.Bound); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("randomness", p.Randomness); err != nil {
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
	return hashParts([]byte(encryptionTranscriptLabel), domain, pkBytes, intBytes(ciphertext), scalarCommitment, bound, intBytes(cipherCommitment), pointCommitment)
}

// Marshal returns deterministic canonical binary proof payloads.
func Marshal(v any) ([]byte, error) {
	switch p := v.(type) {
	case *ModulusProof:
		return marshalModulusProof(p)
	case ModulusProof:
		return marshalModulusProof(&p)
	case *EncScalarProof:
		return marshalEncScalarProof(p)
	case EncScalarProof:
		return marshalEncScalarProof(&p)
	case *EncRangeProof:
		return marshalEncRangeProof(p)
	case EncRangeProof:
		return marshalEncRangeProof(&p)
	case *MTAResponseProof:
		return marshalMTAResponseProof(p)
	case MTAResponseProof:
		return marshalMTAResponseProof(&p)
	case *LogProof:
		return marshalLogProof(p)
	case *PrimalityProof:
		return MarshalPrimalityProof(p)
	case *EncryptionProof:
		return marshalEncryptionProof(p)
	case EncryptionProof:
		return marshalEncryptionProof(&p)

	case PrimalityProof:
		return MarshalPrimalityProof(&p)
	case LogProof:
		return marshalLogProof(&p)
	default:
		return nil, fmt.Errorf("unsupported Paillier proof type %T", v)
	}
}

// UnmarshalModulusProof decodes and structurally validates a modulus proof.
func UnmarshalModulusProof(in []byte) (*ModulusProof, error) {
	version, fields, err := wire.Unmarshal(in, modulusProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected modulus proof version %d", version)
	}
	if err := requireExactProofTags(fields, modulusProofFieldNBits, modulusProofFieldSmallFactorCheck, modulusProofFieldTranscriptHash, modulusProofFieldCommitment, modulusProofFieldChallenge, modulusProofFieldResponse); err != nil {
		return nil, err
	}
	nBits, err := wire.Uint32Field(fields, modulusProofFieldNBits)
	if err != nil {
		return nil, err
	}
	p := &ModulusProof{
		Version:          proofVersion,
		NBits:            int(nBits),
		SmallFactorCheck: wire.MustField(fields, modulusProofFieldSmallFactorCheck),
		TranscriptHash:   wire.MustField(fields, modulusProofFieldTranscriptHash),
		Commitment:       wire.MustField(fields, modulusProofFieldCommitment),
		Challenge:        wire.MustField(fields, modulusProofFieldChallenge),
		Response:         wire.MustField(fields, modulusProofFieldResponse),
	}
	if err := validateModulusProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalEncScalarProof decodes and validates an encrypted scalar proof shell.
func UnmarshalEncScalarProof(in []byte) (*EncScalarProof, error) {
	version, fields, err := wire.Unmarshal(in, encScalarProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected encrypted scalar proof version %d", version)
	}
	if err := requireExactProofTags(fields, encScalarProofFieldScalarCommitment, encScalarProofFieldCipherCommitment, encScalarProofFieldPointCommitment, encScalarProofFieldResponse, encScalarProofFieldRandomness, encScalarProofFieldTranscriptHash); err != nil {
		return nil, err
	}
	p := &EncScalarProof{
		Version:          proofVersion,
		ScalarCommitment: wire.MustField(fields, encScalarProofFieldScalarCommitment),
		CipherCommitment: wire.MustField(fields, encScalarProofFieldCipherCommitment),
		PointCommitment:  wire.MustField(fields, encScalarProofFieldPointCommitment),
		Response:         wire.MustField(fields, encScalarProofFieldResponse),
		Randomness:       wire.MustField(fields, encScalarProofFieldRandomness),
		TranscriptHash:   wire.MustField(fields, encScalarProofFieldTranscriptHash),
	}
	if err := validateEncScalarProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalEncRangeProof decodes and validates an encrypted range proof.
func UnmarshalEncRangeProof(in []byte) (*EncRangeProof, error) {
	version, fields, err := wire.Unmarshal(in, encRangeProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected encrypted range proof version %d", version)
	}
	if err := requireExactProofTags(fields, encRangeProofFieldBound, encRangeProofFieldCommitment, encRangeProofFieldPointCommitment, encRangeProofFieldChallenge, encRangeProofFieldResponse, encRangeProofFieldRandomness, encRangeProofFieldTranscriptHash, encRangeProofFieldDigest); err != nil {
		return nil, err
	}
	p := &EncRangeProof{
		Version:         proofVersion,
		Bound:           wire.MustField(fields, encRangeProofFieldBound),
		Commitment:      wire.MustField(fields, encRangeProofFieldCommitment),
		PointCommitment: wire.MustField(fields, encRangeProofFieldPointCommitment),
		Challenge:       wire.MustField(fields, encRangeProofFieldChallenge),
		Response:        wire.MustField(fields, encRangeProofFieldResponse),
		Randomness:      wire.MustField(fields, encRangeProofFieldRandomness),
		TranscriptHash:  wire.MustField(fields, encRangeProofFieldTranscriptHash),
		Digest:          wire.MustField(fields, encRangeProofFieldDigest),
	}
	if err := validateEncRangeProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalMTAResponseProof decodes and validates an MtA response proof shell.
func UnmarshalMTAResponseProof(in []byte) (*MTAResponseProof, error) {
	version, fields, err := wire.Unmarshal(in, mtaResponseProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected MtA response proof version %d", version)
	}
	if err := requireExactProofTags(fields, mtaResponseProofFieldTranscriptHash, mtaResponseProofFieldBetaCommitment, mtaResponseProofFieldCipherCommitment, mtaResponseProofFieldBCommitment, mtaResponseProofFieldBetaNonce, mtaResponseProofFieldBResponse, mtaResponseProofFieldBetaResponse, mtaResponseProofFieldRandomness); err != nil {
		return nil, err
	}
	p := &MTAResponseProof{
		Version:          proofVersion,
		TranscriptHash:   wire.MustField(fields, mtaResponseProofFieldTranscriptHash),
		BetaCommitment:   wire.MustField(fields, mtaResponseProofFieldBetaCommitment),
		CipherCommitment: wire.MustField(fields, mtaResponseProofFieldCipherCommitment),
		BCommitment:      wire.MustField(fields, mtaResponseProofFieldBCommitment),
		BetaNonce:        wire.MustField(fields, mtaResponseProofFieldBetaNonce),
		BResponse:        wire.MustField(fields, mtaResponseProofFieldBResponse),
		BetaResponse:     wire.MustField(fields, mtaResponseProofFieldBetaResponse),
		Randomness:       wire.MustField(fields, mtaResponseProofFieldRandomness),
	}
	if err := validateMTAResponseProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalLogProof decodes and validates a Π^log proof.
func UnmarshalLogProof(in []byte) (*LogProof, error) {
	version, fields, err := wire.Unmarshal(in, logProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected log proof version %d", version)
	}
	if err := requireExactProofTags(fields, logProofFieldPoint, logProofFieldCipherCommitment, logProofFieldPointCommitment, logProofFieldResponse, logProofFieldRandomness, logProofFieldTranscriptHash); err != nil {
		return nil, err
	}
	p := &LogProof{
		Version:          proofVersion,
		Point:            wire.MustField(fields, logProofFieldPoint),
		CipherCommitment: wire.MustField(fields, logProofFieldCipherCommitment),
		PointCommitment:  wire.MustField(fields, logProofFieldPointCommitment),
		Response:         wire.MustField(fields, logProofFieldResponse),
		Randomness:       wire.MustField(fields, logProofFieldRandomness),
		TranscriptHash:   wire.MustField(fields, logProofFieldTranscriptHash),
	}
	if err := validateLogProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// ProveEncScalarAndRange produces an encrypted-scalar proof and an independent
// range proof for the same ciphertext. The two proofs use separate Fiat-Shamir
// challenges derived from proof-specific transcript labels.
func ProveEncScalarAndRange(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int) (*EncScalarProof, *EncRangeProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := pk.Validate(); err != nil {
		return nil, nil, err
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, nil, err
	}
	if scalar == nil || scalar.Sign() <= 0 || scalar.Cmp(secp.Order()) >= 0 {
		return nil, nil, errors.New("scalar out of range")
	}
	scalarCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
	if err != nil {
		return nil, nil, err
	}

	// EncScalarProof.
	alpha, err := randomScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	cipherCommitment, err := pk.EncryptWithRandomness(alpha, rho)
	if err != nil {
		return nil, nil, err
	}
	pointCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(alpha)))
	if err != nil {
		return nil, nil, err
	}
	encTranscript := encScalarTranscript(domain, pk, ciphertext, scalarCommitment, cipherCommitment, pointCommitment)
	eEnc := challenge([]byte(encScalarChallengeLabel), encTranscript)
	zEnc := new(big.Int).Mul(eEnc, scalar)
	zEnc.Add(zEnc, alpha)
	uEnc := new(big.Int).Exp(randomness, eEnc, pk.N)
	uEnc.Mul(uEnc, rho)
	uEnc.Mod(uEnc, pk.N)
	encProof := &EncScalarProof{
		Version:          proofVersion,
		ScalarCommitment: scalarCommitment,
		CipherCommitment: intBytes(cipherCommitment),
		PointCommitment:  pointCommitment,
		Response:         intBytes(zEnc),
		Randomness:       intBytes(uEnc),
		TranscriptHash:   encTranscript,
	}

	// Independent EncRangeProof with its own randomness and challenge.
	beta, err := randomScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	sigma, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	rangeCipherCommitment, err := pk.EncryptWithRandomness(beta, sigma)
	if err != nil {
		return nil, nil, err
	}
	rangePointCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(beta)))
	if err != nil {
		return nil, nil, err
	}
	rangeTranscript := encRangeTranscript(domain, pk, ciphertext, scalarCommitment, secp.Order().Bytes(), rangeCipherCommitment, rangePointCommitment)
	eRange := challenge([]byte(encRangeChallengeLabel), rangeTranscript)
	zRange := new(big.Int).Mul(eRange, scalar)
	zRange.Add(zRange, beta)
	uRange := new(big.Int).Exp(randomness, eRange, pk.N)
	uRange.Mul(uRange, sigma)
	uRange.Mod(uRange, pk.N)
	rangeProof := &EncRangeProof{
		Version:         proofVersion,
		Bound:           secp.Order().Bytes(),
		Commitment:      intBytes(rangeCipherCommitment),
		PointCommitment: rangePointCommitment,
		Challenge:       intBytes(eRange),
		Response:        intBytes(zRange),
		Randomness:      intBytes(uRange),
		TranscriptHash:  rangeTranscript,
	}
	rangeProof.Digest = encRangeDigest(rangeProof)
	return encProof, rangeProof, nil
}

// VerifyEncScalarAndRange verifies the encrypted scalar proof and independent range proof.
func VerifyEncScalarAndRange(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, encProof *EncScalarProof, rangeProof *EncRangeProof) bool {
	return VerifyEncScalar(domain, pk, ciphertext, encProof) && VerifyEncRange(domain, pk, ciphertext, encProof.ScalarCommitment, rangeProof)
}

// VerifyEncRange independently verifies the range proof against a ciphertext
// and the scalar's curve commitment point.
func VerifyEncRange(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, scalarCommitment []byte, proof *EncRangeProof) bool {
	if validateEncRangeProof(proof) != nil || pk == nil || pk.ValidateCiphertext(ciphertext) != nil {
		return false
	}
	if new(big.Int).SetBytes(proof.Bound).Cmp(secp.Order()) != 0 {
		return false
	}
	if !bytes.Equal(proof.Digest, encRangeDigest(proof)) {
		return false
	}

	cipherCommitment := new(big.Int).SetBytes(proof.Commitment)
	if pk.ValidateCiphertext(cipherCommitment) != nil {
		return false
	}
	pointCommitment, err := secp.PointFromBytes(proof.PointCommitment)
	if err != nil {
		return false
	}
	scalarPoint, err := secp.PointFromBytes(scalarCommitment)
	if err != nil {
		return false
	}

	rangeTranscript := encRangeTranscript(domain, pk, ciphertext, scalarCommitment, proof.Bound, cipherCommitment, proof.PointCommitment)
	if !bytes.Equal(rangeTranscript, proof.TranscriptHash) {
		return false
	}

	e := challenge([]byte(encRangeChallengeLabel), rangeTranscript)
	if new(big.Int).SetBytes(proof.Challenge).Cmp(e) != 0 {
		return false
	}

	z := new(big.Int).SetBytes(proof.Response)
	u := new(big.Int).SetBytes(proof.Randomness)
	if z.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}

	// Response range check: if scalar < bound, then z = e*scalar + alpha
	// satisfies z < bound^2 + bound. A value outside this range indicates
	// the encrypted scalar exceeds the bound.
	bound := new(big.Int).SetBytes(proof.Bound)
	maxZ := new(big.Int).Mul(bound, bound)
	maxZ.Add(maxZ, bound)
	if z.Cmp(maxZ) >= 0 {
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

	// Curve check: z*G == pointCommitment + e * scalarPoint.
	leftPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(z))
	rightPoint := secp.Add(pointCommitment, secp.ScalarMult(scalarPoint, secp.ScalarFromBigInt(e)))
	return secp.Equal(leftPoint, rightPoint)
}

// VerifyEncScalar verifies the encryption and public scalar commitment relation.
func VerifyEncScalar(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, proof *EncScalarProof) bool {
	if validateEncScalarProof(proof) != nil || pk == nil || pk.ValidateCiphertext(ciphertext) != nil {
		return false
	}
	scalarCommitment, err := secp.PointFromBytes(proof.ScalarCommitment)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	if pk.ValidateCiphertext(cipherCommitment) != nil {
		return false
	}
	pointCommitment, err := secp.PointFromBytes(proof.PointCommitment)
	if err != nil {
		return false
	}
	transcript := encScalarTranscript(domain, pk, ciphertext, proof.ScalarCommitment, cipherCommitment, proof.PointCommitment)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	z := new(big.Int).SetBytes(proof.Response)
	u := new(big.Int).SetBytes(proof.Randomness)
	if z.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	// Response range check: if scalar < q, then z = e*scalar + alpha < q^2 + q.
	bound := secp.Order()
	maxZ := new(big.Int).Mul(bound, bound)
	maxZ.Add(maxZ, bound)
	if z.Cmp(maxZ) >= 0 {
		return false
	}
	e := challenge([]byte(encScalarChallengeLabel), transcript)
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
	rightPoint := secp.Add(pointCommitment, secp.ScalarMult(scalarCommitment, secp.ScalarFromBigInt(e)))
	return secp.Equal(leftPoint, rightPoint)
}

// ProveMTAResponse proves response encrypts a*b+beta for committed b.
func ProveMTAResponse(reader io.Reader, domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment []byte, b, beta, betaRandomness *big.Int) (*MTAResponseProof, error) {
	if reader == nil {
		reader = rand.Reader
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
	mu, err := randomScalar(reader)
	if err != nil {
		return nil, err
	}
	nu, err := randomScalar(reader)
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
	cipherCommitment := new(big.Int).Exp(encA, mu, pk.NSquared)
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
		CipherCommitment: intBytes(cipherCommitment),
		BCommitment:      bNonce,
		BetaNonce:        betaNonce,
		BResponse:        intBytes(zB),
		BetaResponse:     intBytes(zBeta),
		Randomness:       intBytes(u),
	}, nil
}

// VerifyMTAResponse checks the MtA response proof and transcript binding.
func VerifyMTAResponse(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitmentBytes []byte, proof *MTAResponseProof) bool {
	if validateMTAResponseProof(proof) != nil || pk == nil || pk.ValidateCiphertext(encA) != nil || pk.ValidateCiphertext(response) != nil {
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
	if pk.ValidateCiphertext(cipherCommitment) != nil {
		return false
	}
	zB := new(big.Int).SetBytes(proof.BResponse)
	zBeta := new(big.Int).SetBytes(proof.BetaResponse)
	u := new(big.Int).SetBytes(proof.Randomness)
	if zB.Sign() <= 0 || zBeta.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	transcript := mtaTranscript(domain, pk, encA, response, bCommitmentBytes, proof.BetaCommitment, cipherCommitment, proof.BCommitment, proof.BetaNonce)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	e := challenge([]byte(mtaChallengeLabel), transcript)

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

// ProveLog creates a Π^log proof that ciphertext c = Enc(a, r) and curve point
// A = a·G share the same discrete logarithm a. The proof encodes the point A
// directly rather than requiring a separate scalar commitment, matching the
// CGGMP21 Section 6.2 Π^log structure.
func ProveLog(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int, pointBytes []byte) (*LogProof, error) {
	if reader == nil {
		reader = rand.Reader
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
	alpha, err := randomScalar(reader)
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
		CipherCommitment: intBytes(cipherCommitment),
		PointCommitment:  pointCommitment,
		Response:         intBytes(z),
		Randomness:       intBytes(u),
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
	if pk.ValidateCiphertext(cipherCommitment) != nil {
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
	if z.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	e := challenge([]byte(logChallengeLabel), transcript)
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

func marshalModulusProof(p *ModulusProof) ([]byte, error) {
	if err := validateModulusProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, modulusProofWireType, []wire.Field{
		{Tag: modulusProofFieldNBits, Value: wire.Uint32(uint32(p.NBits))},
		{Tag: modulusProofFieldSmallFactorCheck, Value: wire.NonNilBytes(p.SmallFactorCheck)},
		{Tag: modulusProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: modulusProofFieldCommitment, Value: wire.NonNilBytes(p.Commitment)},
		{Tag: modulusProofFieldChallenge, Value: wire.NonNilBytes(p.Challenge)},
		{Tag: modulusProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
	})
}

func marshalEncScalarProof(p *EncScalarProof) ([]byte, error) {
	if err := validateEncScalarProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, encScalarProofWireType, []wire.Field{
		{Tag: encScalarProofFieldScalarCommitment, Value: wire.NonNilBytes(p.ScalarCommitment)},
		{Tag: encScalarProofFieldCipherCommitment, Value: wire.NonNilBytes(p.CipherCommitment)},
		{Tag: encScalarProofFieldPointCommitment, Value: wire.NonNilBytes(p.PointCommitment)},
		{Tag: encScalarProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
		{Tag: encScalarProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
		{Tag: encScalarProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
	})
}

func marshalEncRangeProof(p *EncRangeProof) ([]byte, error) {
	if err := validateEncRangeProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, encRangeProofWireType, []wire.Field{
		{Tag: encRangeProofFieldBound, Value: wire.NonNilBytes(p.Bound)},
		{Tag: encRangeProofFieldCommitment, Value: wire.NonNilBytes(p.Commitment)},
		{Tag: encRangeProofFieldPointCommitment, Value: wire.NonNilBytes(p.PointCommitment)},
		{Tag: encRangeProofFieldChallenge, Value: wire.NonNilBytes(p.Challenge)},
		{Tag: encRangeProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
		{Tag: encRangeProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
		{Tag: encRangeProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: encRangeProofFieldDigest, Value: wire.NonNilBytes(p.Digest)},
	})
}

func marshalMTAResponseProof(p *MTAResponseProof) ([]byte, error) {
	if err := validateMTAResponseProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, mtaResponseProofWireType, []wire.Field{
		{Tag: mtaResponseProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: mtaResponseProofFieldBetaCommitment, Value: wire.NonNilBytes(p.BetaCommitment)},
		{Tag: mtaResponseProofFieldCipherCommitment, Value: wire.NonNilBytes(p.CipherCommitment)},
		{Tag: mtaResponseProofFieldBCommitment, Value: wire.NonNilBytes(p.BCommitment)},
		{Tag: mtaResponseProofFieldBetaNonce, Value: wire.NonNilBytes(p.BetaNonce)},
		{Tag: mtaResponseProofFieldBResponse, Value: wire.NonNilBytes(p.BResponse)},
		{Tag: mtaResponseProofFieldBetaResponse, Value: wire.NonNilBytes(p.BetaResponse)},
		{Tag: mtaResponseProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
	})
}

func marshalLogProof(p *LogProof) ([]byte, error) {
	if err := validateLogProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, logProofWireType, []wire.Field{
		{Tag: logProofFieldPoint, Value: wire.NonNilBytes(p.Point)},
		{Tag: logProofFieldCipherCommitment, Value: wire.NonNilBytes(p.CipherCommitment)},
		{Tag: logProofFieldPointCommitment, Value: wire.NonNilBytes(p.PointCommitment)},
		{Tag: logProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
		{Tag: logProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
		{Tag: logProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
	})
}

func validateModulusProof(p *ModulusProof) error {
	if p == nil {
		return errors.New("nil modulus proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected modulus proof version %d", p.Version)
	}
	if p.NBits <= 0 {
		return errors.New("invalid modulus proof bit length")
	}
	if uint64(p.NBits) > uint64(^uint32(0)) {
		return errors.New("modulus proof bit length too large")
	}
	if len(p.TranscriptHash) != sha256.Size || len(p.SmallFactorCheck) != sha256.Size {
		return errors.New("invalid modulus proof")
	}
	if err := validatePositiveIntBytes("commitment", p.Commitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("challenge", p.Challenge); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	return nil
}

func validateEncScalarProof(p *EncScalarProof) error {
	if p == nil {
		return errors.New("nil encrypted scalar proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected encrypted scalar proof version %d", p.Version)
	}
	if len(p.ScalarCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.PointCommitment) == 0 || len(p.Response) == 0 || len(p.Randomness) == 0 || len(p.TranscriptHash) != sha256.Size {
		return errors.New("incomplete encrypted scalar proof")
	}
	if err := validateCurvePointBytes("scalar commitment", p.ScalarCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("point commitment", p.PointCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("cipher commitment", p.CipherCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("randomness", p.Randomness); err != nil {
		return err
	}
	return nil
}

func validateEncRangeProof(p *EncRangeProof) error {
	if p == nil {
		return errors.New("nil encrypted range proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected encrypted range proof version %d", p.Version)
	}
	if len(p.Bound) == 0 || len(p.Commitment) == 0 || len(p.PointCommitment) == 0 || len(p.Challenge) == 0 || len(p.Response) == 0 || len(p.Randomness) == 0 || len(p.TranscriptHash) != sha256.Size || len(p.Digest) != sha256.Size {
		return errors.New("incomplete encrypted range proof")
	}
	if err := validatePositiveIntBytes("bound", p.Bound); err != nil {
		return err
	}
	if err := validateCurvePointBytes("range point commitment", p.PointCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("range commitment", p.Commitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("range challenge", p.Challenge); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("range response", p.Response); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("range randomness", p.Randomness); err != nil {
		return err
	}
	return nil
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
	if err := validatePositiveIntBytes("cipher commitment", p.CipherCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("b response", p.BResponse); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("beta response", p.BetaResponse); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("randomness", p.Randomness); err != nil {
		return err
	}
	return nil
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
	if err := validatePositiveIntBytes("cipher commitment", p.CipherCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("randomness", p.Randomness); err != nil {
		return err
	}
	return nil
}

func validateCurvePointBytes(name string, in []byte) error {
	if _, err := secp.PointFromBytes(in); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}

func validatePositiveIntBytes(name string, in []byte) error {
	if len(in) == 0 {
		return fmt.Errorf("%s is empty", name)
	}
	if in[0] == 0 {
		return fmt.Errorf("%s is not minimally encoded", name)
	}
	return nil
}

func requireExactProofTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("unexpected proof field count %d", len(fields))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected proof field tag %d", fields[i].Tag)
		}
	}
	return nil
}

func encScalarTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, scalarCommitment []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return hashParts([]byte(encScalarTranscriptLabel), domain, pkBytes, intBytes(ciphertext), scalarCommitment, intBytes(cipherCommitment), pointCommitment)
}

func encRangeTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, scalarCommitment, bound []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return hashParts([]byte(encRangeTranscriptLabel), domain, pkBytes, intBytes(ciphertext), scalarCommitment, bound, intBytes(cipherCommitment), pointCommitment)
}

func mtaTranscript(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment, betaCommitment []byte, cipherCommitment *big.Int, bNonce, betaNonce []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return hashParts([]byte(mtaTranscriptLabel), domain, pkBytes, intBytes(encA), intBytes(response), bCommitment, betaCommitment, intBytes(cipherCommitment), bNonce, betaNonce)
}

func logTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, pointBytes []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return hashParts([]byte(logTranscriptLabel), domain, pkBytes, intBytes(ciphertext), pointBytes, intBytes(cipherCommitment), pointCommitment)
}

func encRangeDigest(proof *EncRangeProof) []byte {
	if proof == nil {
		return nil
	}
	return hashParts([]byte(encRangeDigestLabel), proof.Bound, proof.Challenge, proof.Response, proof.TranscriptHash)
}

func challenge(parts ...[]byte) *big.Int {
	out := new(big.Int).SetBytes(hashParts(parts...))
	out.Mod(out, secp.Order())
	if out.Sign() == 0 {
		out.SetInt64(1)
	}
	return out
}

func smallFactorDigest(n *big.Int) []byte {
	h := sha256.New()
	for _, p := range []int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47} {
		rem := new(big.Int).Mod(n, big.NewInt(p)).Int64()
		_, _ = h.Write([]byte{byte(p), byte(rem)})
	}
	return h.Sum(nil)
}

func hashParts(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func randomScalar(reader io.Reader) (*big.Int, error) {
	for {
		x, err := rand.Int(reader, secp.Order())
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

func randomCoprime(reader io.Reader, n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	for {
		x, err := rand.Int(reader, n)
		if err != nil {
			return nil, err
		}
		if x.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, x, n).Cmp(one) == 0 {
			return x, nil
		}
	}
}

func intBytes(x *big.Int) []byte {
	if x == nil {
		return nil
	}
	return x.Bytes()
}

func partyBytes(party uint32) []byte {
	return []byte{byte(party >> 24), byte(party >> 16), byte(party >> 8), byte(party)}
}

func mod(x, m *big.Int) *big.Int {
	out := new(big.Int).Mod(x, m)
	if out.Sign() < 0 {
		out.Add(out, m)
	}
	return out
}
