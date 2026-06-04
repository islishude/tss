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

const proofVersion = 1

// Security parameters for statistical zero-knowledge in Fiat-Shamir proofs.
// l (securityParameter) matches the secp256k1 order bit length.
// ε (statSecurityParam) provides the statistical hiding margin so that
// the mask α ∈ [0, 2^{l+ε}) makes witness recovery from z = α + e·x
// computationally infeasible (~2^ε candidates).
const (
	securityParameter = 256                                   // l, secp256k1 order ≈ 2^256
	statSecurityParam = 128                                   // ε, statistical security parameter
	maskBits          = securityParameter + statSecurityParam // 384
)

const (
	modulusProofWireType       = "zk.paillier.modulus-proof"
	mtaResponseProofWireType   = "zk.paillier.mta-response-proof"
	logProofWireType           = "zk.paillier.log-proof"
	ringPedersenParamsWireType = "zk.paillier.ring-pedersen-params"
	ringPedersenProofWireType  = "zk.paillier.ring-pedersen-proof"
	encryptionProofWireType    = "zk.paillier.encryption-proof"
)

const (
	modulusProofFieldW uint16 = iota + 1
	modulusProofFieldTranscriptHash
	modulusProofFieldX
	modulusProofFieldA
	modulusProofFieldB
	modulusProofFieldZ
)

const (
	ringPedersenParamsFieldN uint16 = iota + 1
	ringPedersenParamsFieldS
	ringPedersenParamsFieldT
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
	ringPedersenProofFieldTranscriptHash uint16 = iota + 1
	ringPedersenProofFieldCommitments
	ringPedersenProofFieldChallenges
	ringPedersenProofFieldResponses
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
	proofTranscriptLabel       = "cggmp24-paillier-proof-transcript-v1"
	modulusProofTag            = "mod"
	modulusYLabel              = "cggmp24-paillier-mod-y-v1"
	ringPedersenProofTag       = "prm"
	ringPedersenChallengeLabel = "cggmp24-paillier-prm-challenge-v1"
	mtaProofTag                = "mta"
	mtaChallengeLabel          = "paillier-mta-response-challenge-v1"
	logProofTag                = "log"
	logChallengeLabel          = "paillier-log-challenge-v1"
	encryptionProofTag         = "enc"
	encryptionChallengeLabel   = "paillier-encryption-challenge-v1"
)

const (
	modulusProofRounds      = 128
	ringPedersenProofRounds = 128

	mtaResponseScalarMaxBytes = 128
)

// ModulusProof is CGGMP24 Πmod for a Paillier-Blum modulus. It proves
// knowledge of the factorization of N using verifier-derived challenges y_i;
// the proof never carries y_i values supplied by the prover.
type ModulusProof struct {
	Version        uint16   `json:"version"`
	W              []byte   `json:"w"`
	TranscriptHash []byte   `json:"transcript_hash"`
	X              [][]byte `json:"x"`
	A              []byte   `json:"a"`
	B              []byte   `json:"b"`
	Z              [][]byte `json:"z"`
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

// RingPedersenParams are CGGMP Ring-Pedersen public parameters. N must match
// the party Paillier modulus and s,t must be non-degenerate elements of Z*_N.
type RingPedersenParams struct {
	N *big.Int
	S *big.Int
	T *big.Int
}

// RingPedersenProof is CGGMP24 Πprm proving knowledge of lambda such that
// s = t^lambda mod N for Ring-Pedersen parameters (N, s, t).
type RingPedersenProof struct {
	Version        uint16   `json:"version"`
	TranscriptHash []byte   `json:"transcript_hash"`
	Commitments    [][]byte `json:"commitments"`
	Challenges     []byte   `json:"challenges"`
	Responses      [][]byte `json:"responses"`
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

// ProveModulus creates the CGGMP24 Πmod proof for a Paillier-Blum modulus.
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
	if err := validateBlumFactors(sk.P, sk.Q); err != nil {
		return nil, err
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nLen := modulusBytes(sk.N)
	phi := paillierPhi(sk)
	invN := new(big.Int).ModInverse(new(big.Int).Mod(sk.N, phi), phi)
	if invN == nil {
		return nil, errors.New("paillier modulus is not invertible modulo phi(N)")
	}

	w, err := randomJacobiMinusOne(reader, sk.N)
	if err != nil {
		return nil, err
	}
	wBytes := fixedModNBytes(w, nLen)
	transcript := proofTranscript(modulusProofTag, domain, [][]byte{partyBytes(party), raw}, [][]byte{wBytes})

	xs := make([][]byte, modulusProofRounds)
	zs := make([][]byte, modulusProofRounds)
	aBits := make([]byte, modulusProofRounds)
	bBits := make([]byte, modulusProofRounds)
	for i := range modulusProofRounds {
		y, err := deriveModulusY(sk.N, transcript, i)
		if err != nil {
			return nil, err
		}
		z, err := expSecretMod(sk.N, y, invN, nLen, nLen)
		if err != nil {
			return nil, fmt.Errorf("modulus proof z round %d: %w", i, err)
		}
		a, b, x, err := fourthRootForModulusProof(sk, w, y)
		if err != nil {
			return nil, fmt.Errorf("modulus proof fourth root round %d: %w", i, err)
		}
		xs[i] = fixedModNBytes(x, nLen)
		zs[i] = fixedModNBytes(z, nLen)
		aBits[i] = byte(a)
		bBits[i] = byte(b)
	}
	return &ModulusProof{
		Version:        proofVersion,
		W:              wBytes,
		TranscriptHash: transcript,
		X:              xs,
		A:              aBits,
		B:              bBits,
		Z:              zs,
	}, nil
}

// VerifyModulus checks the CGGMP24 Πmod proof against a public key and domain.
func VerifyModulus(domain []byte, pk *pai.PublicKey, party uint32, proof *ModulusProof) bool {
	if validateModulusProof(proof) != nil || pk == nil {
		return false
	}
	if err := pk.Validate(); err != nil {
		return false
	}
	if pk.N.ProbablyPrime(64) || pk.N.Bit(0) == 0 {
		return false
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		return false
	}
	nLen := modulusBytes(pk.N)
	w, err := decodeFixedUnit("modulus proof w", proof.W, pk.N, nLen)
	if err != nil {
		return false
	}
	if big.Jacobi(w, pk.N) != -1 {
		return false
	}
	expectedTranscript := proofTranscript(modulusProofTag, domain, [][]byte{partyBytes(party), raw}, [][]byte{proof.W})
	if !bytes.Equal(expectedTranscript, proof.TranscriptHash) {
		return false
	}
	for i := range modulusProofRounds {
		x, err := decodeFixedUnit("modulus proof x", proof.X[i], pk.N, nLen)
		if err != nil {
			return false
		}
		z, err := decodeFixedUnit("modulus proof z", proof.Z[i], pk.N, nLen)
		if err != nil {
			return false
		}
		y, err := deriveModulusY(pk.N, expectedTranscript, i)
		if err != nil {
			return false
		}
		leftZ := new(big.Int).Exp(z, pk.N, pk.N)
		if leftZ.Cmp(y) != 0 {
			return false
		}
		leftX := new(big.Int).Exp(x, big.NewInt(4), pk.N)
		right := new(big.Int).Set(y)
		if proof.B[i] == 1 {
			right.Mul(right, w)
			right.Mod(right, pk.N)
		}
		if proof.A[i] == 1 {
			right.Neg(right)
			right.Mod(right, pk.N)
		}
		if leftX.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

// GenerateRingPedersenParams creates Ring-Pedersen public parameters tied to
// sk.N and returns the secret lambda needed to prove Πprm.
func GenerateRingPedersenParams(reader io.Reader, sk *pai.PrivateKey) (*RingPedersenParams, *big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, nil, errors.New("nil Paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, nil, err
	}
	phi := paillierPhi(sk)
	nLen := modulusBytes(sk.N)
	var lambda *big.Int
	for {
		v, err := rand.Int(reader, phi)
		if err != nil {
			return nil, nil, err
		}
		if v.Sign() != 0 {
			lambda = v
			break
		}
	}
	for {
		t, err := randomCoprime(reader, sk.N)
		if err != nil {
			return nil, nil, err
		}
		if t.Cmp(big.NewInt(1)) <= 0 {
			continue
		}
		s, err := expSecretMod(sk.N, t, lambda, nLen, nLen)
		if err != nil {
			return nil, nil, err
		}
		if s.Cmp(big.NewInt(1)) <= 0 {
			continue
		}
		params := &RingPedersenParams{
			N: new(big.Int).Set(sk.N),
			S: s,
			T: t,
		}
		if err := ValidateRingPedersenParams(params); err != nil {
			continue
		}
		return params, lambda, nil
	}
}

// ProveRingPedersen creates CGGMP24 Πprm for Ring-Pedersen parameters.
func ProveRingPedersen(reader io.Reader, domain []byte, sk *pai.PrivateKey, params *RingPedersenParams, lambda *big.Int, party uint32) (*RingPedersenProof, error) {
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
	if lambda == nil || lambda.Sign() <= 0 {
		return nil, errors.New("invalid Ring-Pedersen lambda")
	}
	nLen := modulusBytes(sk.N)
	s, err := expSecretMod(sk.N, params.T, lambda, nLen, nLen)
	if err != nil {
		return nil, err
	}
	if s.Cmp(params.S) != 0 {
		return nil, errors.New("Ring-Pedersen lambda does not open s")
	}
	phi := paillierPhi(sk)
	commitments := make([][]byte, ringPedersenProofRounds)
	nonces := make([]*big.Int, ringPedersenProofRounds)
	for i := range ringPedersenProofRounds {
		nonce, err := rand.Int(reader, phi)
		if err != nil {
			return nil, err
		}
		commitment, err := expSecretMod(sk.N, params.T, nonce, nLen, nLen)
		if err != nil {
			return nil, err
		}
		nonces[i] = nonce
		commitments[i] = fixedModNBytes(commitment, nLen)
	}
	transcript := ringPedersenTranscript(domain, params, party, commitments)
	challenges := make([]byte, ringPedersenProofRounds)
	responses := make([][]byte, ringPedersenProofRounds)
	for i := range ringPedersenProofRounds {
		e := ringPedersenChallenge(transcript, i)
		challenges[i] = e
		z := new(big.Int).Set(nonces[i])
		if e == 1 {
			z.Add(z, lambda)
		}
		z.Mod(z, phi)
		responses[i] = fixedModNBytes(z, nLen)
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

// MarshalRingPedersenParams encodes Ring-Pedersen parameters canonically.
func MarshalRingPedersenParams(params *RingPedersenParams) ([]byte, error) {
	if err := ValidateRingPedersenParams(params); err != nil {
		return nil, err
	}
	nLen := modulusBytes(params.N)
	return wire.Marshal(proofVersion, ringPedersenParamsWireType, []wire.Field{
		{Tag: ringPedersenParamsFieldN, Value: fixedModNBytes(params.N, nLen)},
		{Tag: ringPedersenParamsFieldS, Value: fixedModNBytes(params.S, nLen)},
		{Tag: ringPedersenParamsFieldT, Value: fixedModNBytes(params.T, nLen)},
	})
}

// UnmarshalRingPedersenParams decodes Ring-Pedersen parameters.
func UnmarshalRingPedersenParams(in []byte) (*RingPedersenParams, error) {
	version, fields, err := wire.Unmarshal(in, ringPedersenParamsWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected Ring-Pedersen parameter version %d", version)
	}
	if err := requireExactProofTags(fields, ringPedersenParamsFieldN, ringPedersenParamsFieldS, ringPedersenParamsFieldT); err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(wire.MustField(fields, ringPedersenParamsFieldN))
	nLen := modulusBytes(n)
	if nLen == 0 || len(wire.MustField(fields, ringPedersenParamsFieldN)) != nLen {
		return nil, errors.New("invalid Ring-Pedersen modulus encoding")
	}
	sRaw := wire.MustField(fields, ringPedersenParamsFieldS)
	tRaw := wire.MustField(fields, ringPedersenParamsFieldT)
	if len(sRaw) != nLen || len(tRaw) != nLen {
		return nil, errors.New("invalid Ring-Pedersen parameter width")
	}
	params := &RingPedersenParams{
		N: n,
		S: new(big.Int).SetBytes(sRaw),
		T: new(big.Int).SetBytes(tRaw),
	}
	if err := ValidateRingPedersenParams(params); err != nil {
		return nil, err
	}
	return params, nil
}

func marshalRingPedersenProof(p *RingPedersenProof) ([]byte, error) {
	if err := validateRingPedersenProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, ringPedersenProofWireType, []wire.Field{
		{Tag: ringPedersenProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: ringPedersenProofFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
		{Tag: ringPedersenProofFieldChallenges, Value: wire.NonNilBytes(p.Challenges)},
		{Tag: ringPedersenProofFieldResponses, Value: wire.EncodeBytesList(p.Responses)},
	})
}

// UnmarshalRingPedersenProof decodes and structurally validates Πprm.
func UnmarshalRingPedersenProof(in []byte) (*RingPedersenProof, error) {
	version, fields, err := wire.Unmarshal(in, ringPedersenProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected Ring-Pedersen proof version %d", version)
	}
	if err := requireExactProofTags(fields, ringPedersenProofFieldTranscriptHash, ringPedersenProofFieldCommitments, ringPedersenProofFieldChallenges, ringPedersenProofFieldResponses); err != nil {
		return nil, err
	}
	commitments, err := wire.BytesListField(fields, ringPedersenProofFieldCommitments)
	if err != nil {
		return nil, err
	}
	responses, err := wire.BytesListField(fields, ringPedersenProofFieldResponses)
	if err != nil {
		return nil, err
	}
	p := &RingPedersenProof{
		Version:        proofVersion,
		TranscriptHash: wire.MustField(fields, ringPedersenProofFieldTranscriptHash),
		Commitments:    commitments,
		Challenges:     wire.MustField(fields, ringPedersenProofFieldChallenges),
		Responses:      responses,
	}
	if err := validateRingPedersenProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

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

// Marshal returns deterministic canonical binary proof payloads.
func Marshal(v any) ([]byte, error) {
	switch p := v.(type) {
	case *ModulusProof:
		return marshalModulusProof(p)
	case ModulusProof:
		return marshalModulusProof(&p)
	case *MTAResponseProof:
		return marshalMTAResponseProof(p)
	case MTAResponseProof:
		return marshalMTAResponseProof(&p)
	case *LogProof:
		return marshalLogProof(p)
	case *RingPedersenProof:
		return marshalRingPedersenProof(p)
	case RingPedersenProof:
		return marshalRingPedersenProof(&p)
	case *EncryptionProof:
		return marshalEncryptionProof(p)
	case EncryptionProof:
		return marshalEncryptionProof(&p)

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
	if err := requireExactProofTags(fields, modulusProofFieldW, modulusProofFieldTranscriptHash, modulusProofFieldX, modulusProofFieldA, modulusProofFieldB, modulusProofFieldZ); err != nil {
		return nil, err
	}
	xs, err := wire.BytesListField(fields, modulusProofFieldX)
	if err != nil {
		return nil, err
	}
	zs, err := wire.BytesListField(fields, modulusProofFieldZ)
	if err != nil {
		return nil, err
	}
	p := &ModulusProof{
		Version:        proofVersion,
		W:              wire.MustField(fields, modulusProofFieldW),
		TranscriptHash: wire.MustField(fields, modulusProofFieldTranscriptHash),
		X:              xs,
		A:              wire.MustField(fields, modulusProofFieldA),
		B:              wire.MustField(fields, modulusProofFieldB),
		Z:              zs,
	}
	if err := validateModulusProof(p); err != nil {
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

// ProveLog creates a Π^log proof that ciphertext c = Enc(a, r) and curve point
// A = a·G share the same discrete logarithm a. The proof encodes the point A
// directly rather than requiring a separate scalar commitment, matching the
// CGGMP21 Section 6.2 Π^log structure.
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

func marshalModulusProof(p *ModulusProof) ([]byte, error) {
	if err := validateModulusProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, modulusProofWireType, []wire.Field{
		{Tag: modulusProofFieldW, Value: wire.NonNilBytes(p.W)},
		{Tag: modulusProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: modulusProofFieldX, Value: wire.EncodeBytesList(p.X)},
		{Tag: modulusProofFieldA, Value: wire.NonNilBytes(p.A)},
		{Tag: modulusProofFieldB, Value: wire.NonNilBytes(p.B)},
		{Tag: modulusProofFieldZ, Value: wire.EncodeBytesList(p.Z)},
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
	if len(p.W) == 0 || len(p.TranscriptHash) != sha256.Size {
		return errors.New("incomplete modulus proof")
	}
	if len(p.X) != modulusProofRounds || len(p.Z) != modulusProofRounds || len(p.A) != modulusProofRounds || len(p.B) != modulusProofRounds {
		return errors.New("invalid modulus proof round count")
	}
	for i := range modulusProofRounds {
		if len(p.X[i]) == 0 || len(p.Z[i]) == 0 {
			return fmt.Errorf("incomplete modulus proof round %d", i)
		}
		if p.A[i] != 0 && p.A[i] != 1 {
			return fmt.Errorf("invalid modulus proof a bit %d", i)
		}
		if p.B[i] != 0 && p.B[i] != 1 {
			return fmt.Errorf("invalid modulus proof b bit %d", i)
		}
	}
	return nil
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

func mtaTranscript(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment, betaCommitment []byte, cipherCommitment *big.Int, bNonce, betaNonce []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return proofTranscript(mtaProofTag, domain,
		[][]byte{pkBytes, fixedModN2Bytes(encA, pk), fixedModN2Bytes(response, pk), bCommitment, betaCommitment},
		[][]byte{fixedModN2Bytes(cipherCommitment, pk), bNonce, betaNonce},
	)
}

func logTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, pointBytes []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return proofTranscript(logProofTag, domain,
		[][]byte{pkBytes, fixedModN2Bytes(ciphertext, pk), pointBytes},
		[][]byte{fixedModN2Bytes(cipherCommitment, pk), pointCommitment},
	)
}

func ringPedersenTranscript(domain []byte, params *RingPedersenParams, party uint32, commitments [][]byte) []byte {
	paramsBytes, _ := MarshalRingPedersenParams(params)
	return proofTranscript(ringPedersenProofTag, domain,
		[][]byte{partyBytes(party), paramsBytes},
		[][]byte{wire.EncodeBytesList(commitments)},
	)
}

func proofTranscript(tag string, domain []byte, statementParts, commitmentParts [][]byte) []byte {
	return hashParts(
		[]byte(proofTranscriptLabel),
		wire.Uint32(uint32(proofVersion)),
		[]byte("secp256k1"),
		[]byte(tag),
		domain,
		wire.EncodeBytesList(statementParts),
		wire.EncodeBytesList(commitmentParts),
	)
}

// challenge returns the full 256-bit SHA-256 hash output as a Fiat-Shamir
// challenge without modular reduction. Used by EncryptionProof, MTAResponseProof,
// and LogProof where a ~256-bit challenge combined with a large mask α ∈ [0,2^384)
// provides statistical zero-knowledge (~2^128 candidate witnesses).
func challenge(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(hashParts(parts...))
}

func ringPedersenChallenge(transcript []byte, round int) byte {
	digest := hashParts([]byte(ringPedersenChallengeLabel), transcript, wire.Uint32(uint32(round)))
	return digest[0] & 1
}

func deriveModulusY(n *big.Int, transcript []byte, round int) (*big.Int, error) {
	if n == nil || n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return nil, errors.New("invalid modulus")
	}
	nLen := modulusBytes(n)
	for counter := uint32(0); ; counter++ {
		candidate := new(big.Int).SetBytes(expandHash(nLen, []byte(modulusYLabel), transcript, wire.Uint32(uint32(round)), wire.Uint32(counter)))
		candidate.Mod(candidate, n)
		if _, err := requireUnit(candidate, n); err != nil {
			continue
		}
		return candidate, nil
	}
}

func randomJacobiMinusOne(reader io.Reader, n *big.Int) (*big.Int, error) {
	for {
		w, err := randomCoprime(reader, n)
		if err != nil {
			return nil, err
		}
		if big.Jacobi(w, n) == -1 {
			return w, nil
		}
	}
}

func fourthRootForModulusProof(sk *pai.PrivateKey, w, y *big.Int) (int, int, *big.Int, error) {
	for a := 0; a <= 1; a++ {
		for b := 0; b <= 1; b++ {
			target := new(big.Int).Set(y)
			if b == 1 {
				target.Mul(target, w)
				target.Mod(target, sk.N)
			}
			if a == 1 {
				target.Neg(target)
				target.Mod(target, sk.N)
			}
			if !isQuadraticResidueComposite(target, sk.P, sk.Q) {
				continue
			}
			root, err := fourthRootBlum(sk, target)
			if err != nil {
				return 0, 0, nil, err
			}
			check := new(big.Int).Exp(root, big.NewInt(4), sk.N)
			if check.Cmp(target) != 0 {
				continue
			}
			return a, b, root, nil
		}
	}
	return 0, 0, nil, errors.New("no quadratic-residue adjustment found")
}

func fourthRootBlum(sk *pai.PrivateKey, target *big.Int) (*big.Int, error) {
	phi := paillierPhi(sk)
	sqrtExp := new(big.Int).Add(phi, big.NewInt(4))
	sqrtExp.Rsh(sqrtExp, 3)
	fourthExp := new(big.Int).Mul(sqrtExp, sqrtExp)
	nLen := modulusBytes(sk.N)
	return expSecretMod(sk.N, target, fourthExp, nLen, 2*nLen)
}

func isQuadraticResidueComposite(x, p, q *big.Int) bool {
	return big.Jacobi(new(big.Int).Mod(x, p), p) == 1 && big.Jacobi(new(big.Int).Mod(x, q), q) == 1
}

func expSecretMod(modulus, base, exponent *big.Int, modLen, expLen int) (*big.Int, error) {
	out, err := paillierct.ExpCT(
		paillierct.FixedEncode(modulus, modLen),
		paillierct.FixedEncode(new(big.Int).Mod(base, modulus), modLen),
		paillierct.FixedEncode(exponent, expLen),
	)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(out), nil
}

func paillierPhi(sk *pai.PrivateKey) *big.Int {
	p1 := new(big.Int).Sub(sk.P, big.NewInt(1))
	q1 := new(big.Int).Sub(sk.Q, big.NewInt(1))
	return new(big.Int).Mul(p1, q1)
}

func validateBlumFactors(p, q *big.Int) error {
	if p == nil || q == nil || p.Sign() <= 0 || q.Sign() <= 0 {
		return errors.New("invalid Paillier factors")
	}
	if p.Cmp(q) == 0 {
		return errors.New("paillier factors must differ")
	}
	three := big.NewInt(3)
	four := big.NewInt(4)
	if new(big.Int).Mod(p, four).Cmp(three) != 0 || new(big.Int).Mod(q, four).Cmp(three) != 0 {
		return errors.New("paillier factors must be Blum primes")
	}
	return nil
}

func modulusBytes(n *big.Int) int {
	if n == nil || n.Sign() <= 0 {
		return 0
	}
	return (n.BitLen() + 7) / 8
}

func fixedModNBytes(x *big.Int, nLen int) []byte {
	return paillierct.FixedEncode(x, nLen)
}

func fixedModN2Bytes(x *big.Int, pk *pai.PublicKey) []byte {
	if pk == nil || pk.N == nil {
		return nil
	}
	return paillierct.FixedEncode(x, 2*modulusBytes(pk.N))
}

func fixedScalarBytes(x *big.Int) []byte {
	return paillierct.FixedEncode(x, 32)
}

func validateFixedCiphertextBytes(name string, in []byte, pk *pai.PublicKey) error {
	if pk == nil || pk.N == nil {
		return errors.New("nil Paillier public key")
	}
	if len(in) != 2*modulusBytes(pk.N) {
		return fmt.Errorf("%s has invalid width", name)
	}
	c := new(big.Int).SetBytes(in)
	return pk.ValidateCiphertext(c)
}

func decodeFixedUnit(name string, in []byte, n *big.Int, nLen int) (*big.Int, error) {
	if len(in) != nLen {
		return nil, fmt.Errorf("%s has invalid width", name)
	}
	x := new(big.Int).SetBytes(in)
	return requireUnit(x, n)
}

func validateFixedResponse(name string, in []byte, n *big.Int, nLen int) error {
	if len(in) != nLen {
		return fmt.Errorf("%s has invalid width", name)
	}
	x := new(big.Int).SetBytes(in)
	if x.Cmp(n) >= 0 {
		return fmt.Errorf("%s out of range", name)
	}
	return nil
}

func requireUnit(x, n *big.Int) (*big.Int, error) {
	if x == nil || n == nil || x.Sign() <= 0 || x.Cmp(n) >= 0 {
		return nil, errors.New("integer out of range")
	}
	if new(big.Int).GCD(nil, nil, x, n).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("integer is not in the multiplicative group")
	}
	return x, nil
}

func hashParts(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func expandHash(size int, parts ...[]byte) []byte {
	if size <= 0 {
		return nil
	}
	out := make([]byte, 0, size)
	for counter := uint32(0); len(out) < size; counter++ {
		blockParts := make([][]byte, 0, len(parts)+1)
		blockParts = append(blockParts, parts...)
		blockParts = append(blockParts, wire.Uint32(counter))
		out = append(out, hashParts(blockParts...)...)
	}
	return out[:size]
}

// randomLargeMask returns a uniform mask in [0, 2^{l+ε}) for statistical
// zero-knowledge. With l=256 and ε=128, the mask range (~2^384) provides
// ~128 bits of statistical hiding against witness recovery from
// z = α + e·x.
func randomLargeMask(reader io.Reader) (*big.Int, error) {
	return rand.Int(reader, twoToThe(maskBits))
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

// twoToThe returns 2^n as a *big.Int.
func twoToThe(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

// zkRangeBound returns the maximum allowed Fiat-Shamir response for the
// statistical ZK range: 2^{l+ε} + e·q. With l=256, ε=128, and e ∈ [0,2^256),
// z = α + e·m must satisfy z < 2^{l+ε} + e·q.
func zkRangeBound(e *big.Int) *big.Int {
	maxZ := twoToThe(maskBits)
	maxZ.Add(maxZ, new(big.Int).Mul(e, secp.Order()))
	return maxZ
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
