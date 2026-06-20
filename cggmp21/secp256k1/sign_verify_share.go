package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/zk/signprep"
)

const signVerifyShareRecordFixedBytes = 2 + 4*(2+4) + 4

type signVerifyShare struct {
	Party    tss.PartyID     `wire:"1,u32"`
	KPoint   *secp.Point     `wire:"2,custom,len=33"`
	ChiPoint *secp.Point     `wire:"3,custom,len=33"`
	Proof    *signprep.Proof `wire:"4,custom,max_bytes=signprep_proof"`
}

// Clone returns a deep copy of signVerifyShare
func (s signVerifyShare) Clone() signVerifyShare {
	return signVerifyShare{
		Party:    s.Party,
		KPoint:   secp.Clone(s.KPoint),
		ChiPoint: secp.Clone(s.ChiPoint),
		Proof:    s.Proof.Clone(),
	}
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
		size := signVerifyShareRecordFixedBytes + len(kPoint) + len(chiPoint) + len(proof)
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
