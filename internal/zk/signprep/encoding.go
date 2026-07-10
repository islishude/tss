package signprep

import (
	"errors"
	"fmt"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const proofWireVersion = 1
const proofWireType = "zk.signprep.proof"
const (
	proofMaxBytes      = 1024
	proofMaxPointBytes = 65
)

// Validate checks the proof's structural invariants.
// MPoint, MCommitment, and MResponse may be nil when M_i = 0 (point at infinity).
func (p *Proof) Validate() error {
	if p == nil {
		return errors.New("signprep: nil proof")
	}
	mtaIsZero := len(p.MPoint) == 0
	if mtaIsZero && (len(p.MCommitment) != 0 || len(p.MResponse) != 0) {
		return errors.New("signprep: zero MPoint must not carry M proof fields")
	}

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
// wire.Marshal calls Validate via the Validator interface.
func (p *Proof) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(proofFieldLimits()))
}

// UnmarshalBinary decodes a TLV signprep proof record.
func (p *Proof) UnmarshalBinary(in []byte) error {
	var decoded Proof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.FrameLimits{
			MaxTotalBytes: proofMaxBytes,
			MaxFields:     8,
			MaxFieldBytes: proofMaxPointBytes,
		}),
		wire.WithFieldLimits(proofFieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

func proofFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"point":  proofMaxPointBytes,
		"scalar": secp.ScalarSize,
	}
}

// MarshalWireValue encodes the proof as a canonical TLV proof record for
// internal/wire's custom field kind.
func (p *Proof) MarshalWireValue() ([]byte, error) {
	return p.MarshalBinary()
}

// UnmarshalWireValue decodes a canonical TLV proof record for internal/wire's
// custom field kind.
func (p *Proof) UnmarshalWireValue(in []byte) error {
	return p.UnmarshalBinary(in)
}
