package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/zk/signprep"
)

const signVerifyShareRecordFixedBytes = 2 + 10*(2+4) + 4

type signVerifyShare struct {
	Party                 tss.PartyID     `wire:"1,u32"`
	KPoint                *secp.Point     `wire:"2,custom,len=33"`
	ChiPoint              *secp.Point     `wire:"3,custom,len=33"`
	Proof                 *signprep.Proof `wire:"4,custom,max_bytes=signprep_proof"`
	Round2CommitmentsHash []byte          `wire:"5,bytes,len=32"`
	MTAContributionsHash  []byte          `wire:"6,bytes,len=32"`
	MTABasePoint          []byte          `wire:"7,bytes,max_bytes=point"`
	MTAOffsetPoint        []byte          `wire:"8,bytes,max_bytes=point"`
	DeltaBasePoint        []byte          `wire:"9,bytes,max_bytes=point"`
	DeltaOffsetPoint      []byte          `wire:"10,bytes,max_bytes=point"`
	mtaContributions      []presignMTAContribution
}

// Clone returns a deep copy of signVerifyShare
func (s signVerifyShare) Clone() signVerifyShare {
	return signVerifyShare{
		Party:                 s.Party,
		KPoint:                secp.Clone(s.KPoint),
		ChiPoint:              secp.Clone(s.ChiPoint),
		Proof:                 s.Proof.Clone(),
		Round2CommitmentsHash: bytes.Clone(s.Round2CommitmentsHash),
		MTAContributionsHash:  bytes.Clone(s.MTAContributionsHash),
		MTABasePoint:          bytes.Clone(s.MTABasePoint),
		MTAOffsetPoint:        bytes.Clone(s.MTAOffsetPoint),
		DeltaBasePoint:        bytes.Clone(s.DeltaBasePoint),
		DeltaOffsetPoint:      bytes.Clone(s.DeltaOffsetPoint),
		mtaContributions:      cloneMTAContributions(s.mtaContributions),
	}
}

func (s *signVerifyShare) destroy() {
	if s == nil {
		return
	}
	if s.Proof != nil {
		clear(s.Proof.MPoint)
		clear(s.Proof.KCommitment)
		clear(s.Proof.MCommitment)
		clear(s.Proof.DLEQA1)
		clear(s.Proof.DLEQA2)
		clear(s.Proof.MTARelationCommitment)
		clear(s.Proof.DeltaRelationCommitment)
		if s.Proof.KResponse != nil {
			s.Proof.KResponse.Destroy()
		}
		clear(s.Proof.MResponse)
		if s.Proof.DLEQResponse != nil {
			s.Proof.DLEQResponse.Destroy()
		}
	}
	clear(s.Round2CommitmentsHash)
	clear(s.MTAContributionsHash)
	clear(s.MTABasePoint)
	clear(s.MTAOffsetPoint)
	clear(s.DeltaBasePoint)
	clear(s.DeltaOffsetPoint)
	destroyMTAContributions(s.mtaContributions)
	*s = signVerifyShare{}
}

func (s signVerifyShare) kPointBytes() ([]byte, error) {
	return secp.PointBytes(s.KPoint)
}

func (s signVerifyShare) chiPointBytes() ([]byte, error) {
	return secp.PointBytes(s.ChiPoint)
}

func (s signVerifyShare) proofBytes() ([]byte, error) {
	return s.Proof.MarshalBinary()
}

// Validate checks the private sign verification record's structural invariants.
func (s signVerifyShare) Validate() error {
	if s.Party == tss.BroadcastPartyId {
		return errors.New("sign verify share: zero party")
	}
	if _, err := secp.PointBytes(s.KPoint); err != nil {
		return fmt.Errorf("sign verify share: invalid KPoint: %w", err)
	}
	if _, err := secp.PointBytes(s.ChiPoint); err != nil {
		return fmt.Errorf("sign verify share: invalid ChiPoint: %w", err)
	}
	if err := s.Proof.Validate(); err != nil {
		return fmt.Errorf("sign verify share: invalid proof: %w", err)
	}
	if len(s.Round2CommitmentsHash) != sha256.Size {
		return errors.New("sign verify share: round2 commitments hash must be 32 bytes")
	}
	if len(s.MTAContributionsHash) != sha256.Size {
		return errors.New("sign verify share: MTA contributions hash must be 32 bytes")
	}
	if len(s.MTABasePoint) > 0 {
		if _, err := secp.PointFromBytes(s.MTABasePoint); err != nil {
			return fmt.Errorf("sign verify share: invalid MTA base point: %w", err)
		}
	}
	if len(s.MTAOffsetPoint) > 0 {
		if _, err := secp.PointFromBytes(s.MTAOffsetPoint); err != nil {
			return fmt.Errorf("sign verify share: invalid MTA offset point: %w", err)
		}
	}
	if len(s.DeltaBasePoint) > 0 {
		if _, err := secp.PointFromBytes(s.DeltaBasePoint); err != nil {
			return fmt.Errorf("sign verify share: invalid delta base point: %w", err)
		}
	}
	if len(s.DeltaOffsetPoint) > 0 {
		if _, err := secp.PointFromBytes(s.DeltaOffsetPoint); err != nil {
			return fmt.Errorf("sign verify share: invalid delta offset point: %w", err)
		}
	}
	return nil
}

// validateSignVerifyShares checks that the verify shares set matches the signer
// set: one canonically ordered entry per signer, no extras, no duplicates, valid
// typed points/proofs, and aggregate size within limits.
func validateSignVerifyShares(signers tss.PartySet, shares []signVerifyShare, limits Limits) error {
	if len(shares) != len(signers) {
		return fmt.Errorf("verify shares count %d != signers %d", len(shares), len(signers))
	}
	totalBytes := 4 // recordlist item count
	seen := make(map[tss.PartyID]bool, len(shares))
	for i, share := range shares {
		if !tss.ContainsParty(signers, share.Party) {
			return fmt.Errorf("verify share for non-signer party %d", share.Party)
		}
		if seen[share.Party] {
			return fmt.Errorf("duplicate verify share for party %d", share.Party)
		}
		seen[share.Party] = true
		if share.Party != signers[i] {
			return fmt.Errorf("verify share party %d out of canonical signer order at index %d", share.Party, i)
		}
		kPoint, chiPoint, proof, err := signVerifyShareBytes(share)
		if err != nil {
			return fmt.Errorf("verify share party %d: %w", share.Party, err)
		}
		if len(kPoint) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("sign verify share KPoint too large: %d > %d", len(kPoint), limits.Curve.MaxPointBytes)
		}
		if len(chiPoint) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("sign verify share ChiPoint too large: %d > %d", len(chiPoint), limits.Curve.MaxPointBytes)
		}
		if len(proof) > limits.SignPrep.MaxProofBytes {
			return fmt.Errorf("sign verify share proof too large: %d > %d", len(proof), limits.SignPrep.MaxProofBytes)
		}
		size := signVerifyShareRecordFixedBytes + len(kPoint) + len(chiPoint) + len(proof) +
			len(share.Round2CommitmentsHash) + len(share.MTAContributionsHash) +
			len(share.MTABasePoint) + len(share.MTAOffsetPoint) +
			len(share.DeltaBasePoint) + len(share.DeltaOffsetPoint)
		if size > limits.SignPrep.MaxVerifyShareBytes {
			return fmt.Errorf("sign verify share too large: %d > %d", size, limits.SignPrep.MaxVerifyShareBytes)
		}
		totalBytes += 4 + size
	}
	if totalBytes > limits.SignPrep.MaxVerifySharesBytes {
		return fmt.Errorf("verify shares too large: %d > %d", totalBytes, limits.SignPrep.MaxVerifySharesBytes)
	}
	return nil
}

func signVerifyShareBytes(s signVerifyShare) ([]byte, []byte, []byte, error) {
	kPoint, err := s.kPointBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid KPoint: %w", err)
	}
	chiPoint, err := s.chiPointBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid ChiPoint: %w", err)
	}
	if err := s.Proof.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid proof: %w", err)
	}
	proof, err := s.proofBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid proof: %w", err)
	}
	return kPoint, chiPoint, proof, nil
}
