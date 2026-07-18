package paillier

import (
	"bytes"
	"math/big"

	"github.com/islishude/tss/internal/clone"
)

const proofTranscriptVersion = 1

const (
	modulusProofWireType         = "zk.paillier.modulus-proof"
	factorProofWireType          = "zk.paillier.factor-proof"
	ringPedersenParamsType       = "zk.paillier.ring-pedersen-params"
	ringPedersenProofWireType    = "zk.paillier.ring-pedersen-proof"
	modulusProofWireVersion      = 1
	factorProofWireVersion       = 1
	ringPedersenParamsVersion    = 1
	ringPedersenProofWireVersion = 1
)

// FactorProof is CGGMP Pi-fac for proving that a Paillier modulus has no
// small or severely unbalanced factors. The commitments live in the
// verifier's Ring-Pedersen group; all responses are public masked integers.
type FactorProof struct {
	P              *big.Int `wire:"1,bigpos,max_bytes=paillier_modulus"`
	Q              *big.Int `wire:"2,bigpos,max_bytes=paillier_modulus"`
	A              *big.Int `wire:"3,bigpos,max_bytes=paillier_modulus"`
	B              *big.Int `wire:"4,bigpos,max_bytes=paillier_modulus"`
	T              *big.Int `wire:"5,bigpos,max_bytes=paillier_modulus"`
	Sigma          *big.Int `wire:"6,bigint,max_bytes=factor_response"`
	Z1             *big.Int `wire:"7,bigint,max_bytes=factor_response"`
	Z2             *big.Int `wire:"8,bigint,max_bytes=factor_response"`
	W1             *big.Int `wire:"9,bigint,max_bytes=factor_response"`
	W2             *big.Int `wire:"10,bigint,max_bytes=factor_response"`
	V              *big.Int `wire:"11,bigint,max_bytes=factor_response"`
	TranscriptHash []byte   `wire:"12,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for FactorProof.
func (FactorProof) WireType() string { return factorProofWireType }

// WireVersion returns the wire version for FactorProof.
func (FactorProof) WireVersion() uint16 { return factorProofWireVersion }

// Clone returns a deep copy of the proof.
func (p *FactorProof) Clone() *FactorProof {
	if p == nil {
		return nil
	}
	return &FactorProof{
		P: clone.BigInt(p.P), Q: clone.BigInt(p.Q),
		A: clone.BigInt(p.A), B: clone.BigInt(p.B),
		T: clone.BigInt(p.T), Sigma: clone.BigInt(p.Sigma),
		Z1: clone.BigInt(p.Z1), Z2: clone.BigInt(p.Z2),
		W1: clone.BigInt(p.W1), W2: clone.BigInt(p.W2),
		V: clone.BigInt(p.V), TranscriptHash: bytes.Clone(p.TranscriptHash),
	}
}

const (
	proofTranscriptLabel       = "cggmp24-paillier-proof-transcript-v1"
	modulusProofTag            = "mod"
	modulusYLabel              = "cggmp24-paillier-mod-y-v1"
	ringPedersenProofTag       = "prm"
	ringPedersenChallengeLabel = "cggmp24-paillier-prm-challenge-v1"
)

const (
	modulusProofRounds      = 128
	ringPedersenProofRounds = 128
)

// ModulusProof is CGGMP24 Πmod for a Paillier-Blum modulus. It proves
// knowledge of the factorization of N using verifier-derived challenges y_i;
// the proof never carries y_i values supplied by the prover.
type ModulusProof struct {
	W              []byte   `json:"w" wire:"1,bytes,max_bytes=paillier_modulus"`
	TranscriptHash []byte   `json:"transcript_hash" wire:"2,bytes,len=32"`
	X              [][]byte `json:"x" wire:"3,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
	A              []byte   `json:"a" wire:"4,bytes,len=128"`
	B              []byte   `json:"b" wire:"5,bytes,len=128"`
	Z              [][]byte `json:"z" wire:"6,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
}

// WireType returns the canonical wire type identifier for ModulusProof.
func (ModulusProof) WireType() string { return modulusProofWireType }

// WireVersion returns the wire format version for ModulusProof.
func (ModulusProof) WireVersion() uint16 { return modulusProofWireVersion }

// Clone returns a deep copy of the ModulusProof.
func (p *ModulusProof) Clone() *ModulusProof {
	if p == nil {
		return nil
	}
	cp := &ModulusProof{
		W:              bytes.Clone(p.W),
		TranscriptHash: bytes.Clone(p.TranscriptHash),
		X:              clone.ByteSlices(p.X),
		A:              bytes.Clone(p.A),
		B:              bytes.Clone(p.B),
		Z:              clone.ByteSlices(p.Z),
	}
	return cp
}

// Destroy clears all modulus-proof fields.
func (p *ModulusProof) Destroy() {
	if p == nil {
		return
	}
	clear(p.W)
	clear(p.TranscriptHash)
	for _, value := range p.X {
		clear(value)
	}
	clear(p.A)
	clear(p.B)
	for _, value := range p.Z {
		clear(value)
	}
	*p = ModulusProof{}
}

// RingPedersenParams are CGGMP Ring-Pedersen public parameters. N must be an
// independently generated auxiliary modulus distinct from every Paillier
// modulus in a statement; S and T must be non-degenerate elements of Z*_N.
type RingPedersenParams struct {
	N *big.Int `wire:"1,bigpos,max_bits=paillier_modulus_bits"`
	S *big.Int `wire:"2,bigpos,max_bits=paillier_modulus_bits"`
	T *big.Int `wire:"3,bigpos,max_bits=paillier_modulus_bits"`
}

// WireType returns the canonical wire type identifier for RingPedersenParams.
func (RingPedersenParams) WireType() string { return ringPedersenParamsType }

// WireVersion returns the wire format version for RingPedersenParams.
func (RingPedersenParams) WireVersion() uint16 { return ringPedersenParamsVersion }

// Clone returns a deep copy of RingPedersenParams
func (params *RingPedersenParams) Clone() *RingPedersenParams {
	if params == nil {
		return nil
	}
	return &RingPedersenParams{
		N: clone.BigInt(params.N),
		S: clone.BigInt(params.S),
		T: clone.BigInt(params.T),
	}
}

// RingPedersenProof is CGGMP24 Πprm proving knowledge of lambda such that
// s = t^lambda mod N for Ring-Pedersen parameters (N, s, t).
type RingPedersenProof struct {
	TranscriptHash []byte   `json:"transcript_hash" wire:"1,bytes,len=32"`
	Commitments    [][]byte `json:"commitments" wire:"2,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
	Challenges     []byte   `json:"challenges" wire:"3,bytes,len=128"`
	Responses      [][]byte `json:"responses" wire:"4,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
}

// WireType returns the canonical wire type identifier for RingPedersenProof.
func (RingPedersenProof) WireType() string { return ringPedersenProofWireType }

// WireVersion returns the wire format version for RingPedersenProof.
func (RingPedersenProof) WireVersion() uint16 { return ringPedersenProofWireVersion }

// Clone returns a deep copy of the RingPedersenProof.
func (p *RingPedersenProof) Clone() *RingPedersenProof {
	if p == nil {
		return nil
	}
	cp := &RingPedersenProof{
		TranscriptHash: bytes.Clone(p.TranscriptHash),
		Challenges:     bytes.Clone(p.Challenges),
		Commitments:    clone.ByteSlices(p.Commitments),
		Responses:      clone.ByteSlices(p.Responses),
	}
	return cp
}
