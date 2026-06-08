package paillier

import (
	"math/big"
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
