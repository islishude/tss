package signprep

import (
	"errors"
	"fmt"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const proofVersion = 1
const proofWireType = "zk.signprep.proof"

const (
	proofFieldMPoint uint16 = iota + 1
	proofFieldKCommitment
	proofFieldMCommitment
	proofFieldDLEQA1
	proofFieldDLEQA2
	proofFieldKResponse
	proofFieldMResponse
	proofFieldDLEQResponse
)

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
	if _, err := secp.ScalarFromBytes(p.KResponse); err != nil {
		return fmt.Errorf("signprep: invalid KResponse: %w", err)
	}
	if !mtaIsZero {
		if _, err := secp.ScalarFromBytes(p.MResponse); err != nil {
			return fmt.Errorf("signprep: invalid MResponse: %w", err)
		}
	}
	if _, err := secp.ScalarFromBytes(p.DLEQResponse); err != nil {
		return fmt.Errorf("signprep: invalid DLEQResponse: %w", err)
	}
	return nil
}

// MarshalBinary encodes the proof as a deterministic TLV record.
func (p *Proof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, proofWireType, []wire.Field{
		{Tag: proofFieldMPoint, Value: wire.NonNilBytes(p.MPoint)},
		{Tag: proofFieldKCommitment, Value: wire.NonNilBytes(p.KCommitment)},
		{Tag: proofFieldMCommitment, Value: wire.NonNilBytes(p.MCommitment)},
		{Tag: proofFieldDLEQA1, Value: wire.NonNilBytes(p.DLEQA1)},
		{Tag: proofFieldDLEQA2, Value: wire.NonNilBytes(p.DLEQA2)},
		{Tag: proofFieldKResponse, Value: wire.NonNilBytes(p.KResponse)},
		{Tag: proofFieldMResponse, Value: wire.NonNilBytes(p.MResponse)},
		{Tag: proofFieldDLEQResponse, Value: wire.NonNilBytes(p.DLEQResponse)},
	})
}

// UnmarshalProof decodes a deterministic TLV signprep proof record.
func UnmarshalProof(in []byte) (*Proof, error) {
	version, fields, err := wire.Unmarshal(in, proofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected signprep proof version %d", version)
	}
	if err := wire.RequireExactTags(fields, proofFieldMPoint, proofFieldKCommitment, proofFieldMCommitment, proofFieldDLEQA1, proofFieldDLEQA2, proofFieldKResponse, proofFieldMResponse, proofFieldDLEQResponse); err != nil {
		return nil, err
	}
	p := &Proof{
		MPoint:       fields[0].Value,
		KCommitment:  fields[1].Value,
		MCommitment:  fields[2].Value,
		DLEQA1:       fields[3].Value,
		DLEQA2:       fields[4].Value,
		KResponse:    fields[5].Value,
		MResponse:    fields[6].Value,
		DLEQResponse: fields[7].Value,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}
