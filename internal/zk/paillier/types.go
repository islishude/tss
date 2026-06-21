package paillier

import (
	"bytes"
	"math/big"

	"github.com/islishude/tss"
)

const proofTranscriptVersion = 1

const (
	modulusProofWireType         = "zk.paillier.modulus-proof"
	ringPedersenParamsType       = "zk.paillier.ring-pedersen-params"
	ringPedersenProofWireType    = "zk.paillier.ring-pedersen-proof"
	modulusProofWireVersion      = 1
	ringPedersenParamsVersion    = 1
	ringPedersenProofWireVersion = 1
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
func (ModulusProof) WireVersion() uint16 { return modulusProofWireVersion }

// Clone returns a deep copy of the ModulusProof.
func (p *ModulusProof) Clone() *ModulusProof {
	if p == nil {
		return nil
	}
	cp := &ModulusProof{
		W:              bytes.Clone(p.W),
		TranscriptHash: bytes.Clone(p.TranscriptHash),
		X:              tss.CloneByteSlices(p.X),
		A:              bytes.Clone(p.A),
		B:              bytes.Clone(p.B),
		Z:              tss.CloneByteSlices(p.Z),
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
		N: tss.CloneBigInt(params.N),
		S: tss.CloneBigInt(params.S),
		T: tss.CloneBigInt(params.T),
	}
}

// RingPedersenProof is CGGMP24 Πprm proving knowledge of lambda such that
// s = t^lambda mod N for Ring-Pedersen parameters (N, s, t).
type RingPedersenProof struct {
	TranscriptHash []byte   `json:"transcript_hash" wire:"1,bytes"`
	Commitments    [][]byte `json:"commitments" wire:"2,byteslist"`
	Challenges     []byte   `json:"challenges" wire:"3,bytes"`
	Responses      [][]byte `json:"responses" wire:"4,byteslist"`
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
		Commitments:    tss.CloneByteSlices(p.Commitments),
		Responses:      tss.CloneByteSlices(p.Responses),
	}
	return cp
}
