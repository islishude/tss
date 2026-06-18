package paillier

import (
	"math/big"
)

const proofVersion = 1

const (
	modulusProofWireType       = "zk.paillier.modulus-proof"
	ringPedersenParamsWireType = "zk.paillier.ring-pedersen-params"
	ringPedersenProofWireType  = "zk.paillier.ring-pedersen-proof"
)

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

// Clone returns a deep copy of the ModulusProof.
func (p *ModulusProof) Clone() *ModulusProof {
	if p == nil {
		return nil
	}
	cp := &ModulusProof{
		Version:        p.Version,
		W:              append([]byte(nil), p.W...),
		TranscriptHash: append([]byte(nil), p.TranscriptHash...),
		A:              append([]byte(nil), p.A...),
		B:              append([]byte(nil), p.B...),
	}
	for _, x := range p.X {
		cp.X = append(cp.X, append([]byte(nil), x...))
	}
	for _, z := range p.Z {
		cp.Z = append(cp.Z, append([]byte(nil), z...))
	}
	return cp
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
	TranscriptHash []byte   `json:"transcript_hash" wire:"1,bytes"`
	Commitments    [][]byte `json:"commitments" wire:"2,byteslist"`
	Challenges     []byte   `json:"challenges" wire:"3,bytes"`
	Responses      [][]byte `json:"responses" wire:"4,byteslist"`
}

// WireType returns the canonical wire type identifier for RingPedersenProof.
func (RingPedersenProof) WireType() string { return ringPedersenProofWireType }

// WireVersion returns the wire format version for RingPedersenProof.
func (RingPedersenProof) WireVersion() uint16 { return proofVersion }

// Clone returns a deep copy of the RingPedersenProof.
func (p *RingPedersenProof) Clone() *RingPedersenProof {
	if p == nil {
		return nil
	}
	cp := &RingPedersenProof{
		Version:        p.Version,
		TranscriptHash: append([]byte(nil), p.TranscriptHash...),
		Challenges:     append([]byte(nil), p.Challenges...),
	}
	for _, c := range p.Commitments {
		cp.Commitments = append(cp.Commitments, append([]byte(nil), c...))
	}
	for _, r := range p.Responses {
		cp.Responses = append(cp.Responses, append([]byte(nil), r...))
	}
	return cp
}
