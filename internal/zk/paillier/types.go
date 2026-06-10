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
	W              []byte   `json:"w" wire:"1,bytes"`
	TranscriptHash []byte   `json:"transcript_hash" wire:"2,bytes"`
	X              [][]byte `json:"x" wire:"3,byteslist"`
	A              []byte   `json:"a" wire:"4,bytes"`
	B              []byte   `json:"b" wire:"5,bytes"`
	Z              [][]byte `json:"z" wire:"6,byteslist"`
}

// WireType returns the canonical wire type identifier for ModulusProof.
func (ModulusProof) WireType() string { return modulusProofWireType }

// WireVersion returns the wire format version for ModulusProof.
func (ModulusProof) WireVersion() uint16 { return proofVersion }

// MTAResponseProof binds an MtA response to ciphertexts and commitments.
//
// Deprecated: MTAResponseProof is superseded by [AffGProof] for CGGMP-compatible
// MtA response verification. It is only accepted by legacy verifiers in the
// keygen/refresh flows. New code must use [ProveAffG]/[VerifyAffG] instead.
type MTAResponseProof struct {
	Version          uint16 `json:"version"`
	TranscriptHash   []byte `json:"transcript_hash" wire:"1,bytes"`
	BetaCommitment   []byte `json:"beta_commitment" wire:"2,bytes"`
	CipherCommitment []byte `json:"cipher_commitment" wire:"3,bytes"`
	BCommitment      []byte `json:"b_commitment" wire:"4,bytes"`
	BetaNonce        []byte `json:"beta_nonce" wire:"5,bytes"`
	BResponse        []byte `json:"b_response" wire:"6,bytes"`
	BetaResponse     []byte `json:"beta_response" wire:"7,bytes"`
	Randomness       []byte `json:"randomness" wire:"8,bytes"`
}

// WireType returns the canonical wire type identifier for MTAResponseProof.
func (MTAResponseProof) WireType() string { return mtaResponseProofWireType }

// WireVersion returns the wire format version for MTAResponseProof.
func (MTAResponseProof) WireVersion() uint16 { return proofVersion }

// LogProof (Π^log) proves that a Paillier ciphertext c = Enc(a) and a secp256k1
// curve point A = a·G share the same discrete logarithm a. Per CGGMP21
// Section 6.2, this is used during key refresh to prove that a new Paillier
// ciphertext encrypts the same scalar as an existing verification share.
//
// Deprecated: LogProof is superseded by [LogStarProof] for CGGMP-compatible
// discrete-log equality proofs with Ring-Pedersen hiding. It is only accepted
// by legacy verifiers in the keygen/refresh flows. New code must use
// [ProveLogStar]/[VerifyLogStar] instead.
type LogProof struct {
	Version          uint16 `json:"version"`
	Point            []byte `json:"point" wire:"1,bytes"`
	CipherCommitment []byte `json:"cipher_commitment" wire:"2,bytes"`
	PointCommitment  []byte `json:"point_commitment" wire:"3,bytes"`
	Response         []byte `json:"response" wire:"4,bytes"`
	Randomness       []byte `json:"randomness" wire:"5,bytes"`
	TranscriptHash   []byte `json:"transcript_hash" wire:"6,bytes"`
}

// WireType returns the canonical wire type identifier for LogProof.
func (LogProof) WireType() string { return logProofWireType }

// WireVersion returns the wire format version for LogProof.
func (LogProof) WireVersion() uint16 { return proofVersion }

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
	TranscriptHash []byte   `json:"transcript_hash" wire:"1,bytes"`
	Commitments    [][]byte `json:"commitments" wire:"2,byteslist"`
	Challenges     []byte   `json:"challenges" wire:"3,bytes"`
	Responses      [][]byte `json:"responses" wire:"4,byteslist"`
}

// WireType returns the canonical wire type identifier for RingPedersenProof.
func (RingPedersenProof) WireType() string { return ringPedersenProofWireType }

// WireVersion returns the wire format version for RingPedersenProof.
func (RingPedersenProof) WireVersion() uint16 { return proofVersion }

// EncryptionProof (Π^Enc) is a unified Σ-protocol proving that a Paillier
// ciphertext c = Enc(m, r) encrypts a scalar m < q (the secp256k1 order)
// and that the public curve commitment A = m·G opens to the same scalar.
// It combines Π^Eq (scalar knowledge) and the range constraint |m| < q
// into a single Fiat-Shamir challenge. Per CGGMP21 Section 4.1.
//
// Deprecated: EncryptionProof is superseded by [EncProof] for CGGMP-compatible
// encryption-in-range proofs with Ring-Pedersen hiding. It is only used by the
// MtA Start broadcast Round 1 flow where per-verifier Ring-Pedersen commitments
// are impractical. New code must use [ProveEnc]/[VerifyEnc] instead.
type EncryptionProof struct {
	Version          uint16 `json:"version"`
	ScalarCommitment []byte `json:"scalar_commitment" wire:"1,bytes"`
	CipherCommitment []byte `json:"cipher_commitment" wire:"2,bytes"`
	PointCommitment  []byte `json:"point_commitment" wire:"3,bytes"`
	Bound            []byte `json:"bound" wire:"4,bytes"`
	Response         []byte `json:"response" wire:"5,bytes"`
	Randomness       []byte `json:"randomness" wire:"6,bytes"`
	TranscriptHash   []byte `json:"transcript_hash" wire:"7,bytes"`
}

// WireType returns the canonical wire type identifier for EncryptionProof.
func (EncryptionProof) WireType() string { return encryptionProofWireType }

// WireVersion returns the wire format version for EncryptionProof.
func (EncryptionProof) WireVersion() uint16 { return proofVersion }
