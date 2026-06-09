package signprep

import (
	"errors"
	"fmt"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const proofVersion = 1
const proofWireType = "zk.signprep.proof"

// Validate checks the proof's structural invariants.
// MPoint, MCommitment, and MResponse may be nil when M_i = 0 (point at infinity).
func (p *Proof) Validate() error {
	if p == nil {
		return errors.New("signprep: nil proof")
	}
	mtaIsZero := len(p.MPoint) == 0

	if !mtaIsZero {
		if _, err := secp.PointFromBytes(p.MPoint); err != nil {
			return fmt.Errorf("signprep: invalid MPoint: %w", err)
		}
	}
	if _, err := secp.PointFromBytes(p.KCommitment); err != nil {
		return fmt.Errorf("signprep: invalid KCommitment: %w", err)
	}
	if !mtaIsZero {
		if _, err := secp.PointFromBytes(p.MCommitment); err != nil {
			return fmt.Errorf("signprep: invalid MCommitment: %w", err)
		}
	}
	if _, err := secp.PointFromBytes(p.DLEQA1); err != nil {
		return fmt.Errorf("signprep: invalid DLEQA1: %w", err)
	}
	if _, err := secp.PointFromBytes(p.DLEQA2); err != nil {
		return fmt.Errorf("signprep: invalid DLEQA2: %w", err)
	}
	if _, err := secp.ScalarFromBytes(p.KResponse.FixedBytes()); err != nil {
		return fmt.Errorf("signprep: invalid KResponse: %w", err)
	}
	if !mtaIsZero {
		if _, err := secp.ScalarFromBytes(p.MResponse); err != nil {
			return fmt.Errorf("signprep: invalid MResponse: %w", err)
		}
	}
	if _, err := secp.ScalarFromBytes(p.DLEQResponse.FixedBytes()); err != nil {
		return fmt.Errorf("signprep: invalid DLEQResponse: %w", err)
	}
	return nil
}

// MarshalBinary encodes the proof using the object-level wire codec.
func (p *Proof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

// UnmarshalProof decodes a TLV signprep proof record using the object-level wire codec.
func UnmarshalProof(in []byte) (*Proof, error) {
	var p Proof
	if err := wire.Unmarshal(in, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}
