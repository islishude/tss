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
	party    tss.PartyID
	kPoint   *secp.Point
	chiPoint *secp.Point
	proof    signprep.Proof
}

func (s signVerifyShare) clone() signVerifyShare {
	return signVerifyShare{
		party:    s.party,
		kPoint:   secp.Clone(s.kPoint),
		chiPoint: secp.Clone(s.chiPoint),
		proof:    cloneSignPrepProof(s.proof),
	}
}

func (s signVerifyShare) kPointBytes() ([]byte, error) {
	return secp.PointBytes(s.kPoint)
}

func (s signVerifyShare) chiPointBytes() ([]byte, error) {
	return secp.PointBytes(s.chiPoint)
}

func (s signVerifyShare) proofBytes() ([]byte, error) {
	return s.proof.MarshalBinary()
}

type signVerifyShareWire struct {
	Party    tss.PartyID    `wire:"1,u32"`
	KPoint   secp.WirePoint `wire:"2,custom,len=33"`
	ChiPoint secp.WirePoint `wire:"3,custom,len=33"`
	Proof    signprep.Proof `wire:"4,nested,max_bytes=signprep_proof"`
}

// Validate checks the private wire record's structural invariants.
func (w signVerifyShareWire) Validate() error {
	if w.Party == tss.BroadcastPartyId {
		return errors.New("sign verify share: zero party")
	}
	if _, err := secp.PointBytes(w.KPoint.P); err != nil {
		return fmt.Errorf("sign verify share: invalid KPoint: %w", err)
	}
	if _, err := secp.PointBytes(w.ChiPoint.P); err != nil {
		return fmt.Errorf("sign verify share: invalid ChiPoint: %w", err)
	}
	if err := w.Proof.Validate(); err != nil {
		return fmt.Errorf("sign verify share: invalid proof: %w", err)
	}
	return nil
}

func cloneSignPrepProof(p signprep.Proof) signprep.Proof {
	q := (&p).Clone()
	if q == nil {
		return signprep.Proof{}
	}
	return *q
}

func encodeSignVerifyShareWire(s signVerifyShare) signVerifyShareWire {
	return signVerifyShareWire{
		Party:    s.party,
		KPoint:   secp.WirePoint{P: s.kPoint},
		ChiPoint: secp.WirePoint{P: s.chiPoint},
		Proof:    cloneSignPrepProof(s.proof),
	}
}

func decodeSignVerifyShareWire(w signVerifyShareWire) (signVerifyShare, error) {
	if err := w.Validate(); err != nil {
		return signVerifyShare{}, err
	}
	return signVerifyShare{
		party:    w.Party,
		kPoint:   secp.Clone(w.KPoint.P),
		chiPoint: secp.Clone(w.ChiPoint.P),
		proof:    cloneSignPrepProof(w.Proof),
	}, nil
}

func encodeSignVerifyShareWires(shares []signVerifyShare) []signVerifyShareWire {
	out := make([]signVerifyShareWire, 0, len(shares))
	for _, share := range shares {
		out = append(out, encodeSignVerifyShareWire(share))
	}
	return out
}

func decodeSignVerifyShareWires(wires []signVerifyShareWire) ([]signVerifyShare, error) {
	out := make([]signVerifyShare, 0, len(wires))
	for i, w := range wires {
		share, err := decodeSignVerifyShareWire(w)
		if err != nil {
			return nil, fmt.Errorf("verify share %d: %w", i, err)
		}
		out = append(out, share)
	}
	return out, nil
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
		if !tss.ContainsParty(signers, share.party) {
			return fmt.Errorf("verify share for non-signer party %d", share.party)
		}
		if seen[share.party] {
			return fmt.Errorf("duplicate verify share for party %d", share.party)
		}
		seen[share.party] = true
		if share.party != signers[i] {
			return fmt.Errorf("verify share party %d out of canonical signer order at index %d", share.party, i)
		}
		kPoint, chiPoint, proof, err := signVerifyShareBytes(share)
		if err != nil {
			return fmt.Errorf("verify share party %d: %w", share.party, err)
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
	if err := s.proof.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid proof: %w", err)
	}
	proof, err := s.proofBytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid proof: %w", err)
	}
	return kPoint, chiPoint, proof, nil
}
