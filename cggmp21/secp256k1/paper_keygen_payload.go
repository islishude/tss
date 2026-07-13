package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const (
	figure6CommitmentPayloadWireType        = "cggmp21.secp256k1.payload.keygen.figure6-commitment"
	figure6RevealPayloadWireType            = "cggmp21.secp256k1.payload.keygen.figure6-reveal"
	figure6ProofPayloadWireType             = "cggmp21.secp256k1.payload.keygen.figure6-proof"
	figure6PayloadWireVersion        uint16 = 1
)

type figure6CommitmentPayload struct {
	Commitment      []byte `wire:"1,bytes,len=32"`
	ChainCodeCommit []byte `wire:"2,bytes,len=32"`
	PlanHash        []byte `wire:"3,bytes,len=32"`
}

// WireType returns the Figure 6 commitment wire type.
func (figure6CommitmentPayload) WireType() string { return figure6CommitmentPayloadWireType }

// WireVersion returns the Figure 6 commitment wire version.
func (figure6CommitmentPayload) WireVersion() uint16 { return figure6PayloadWireVersion }

// MarshalBinary encodes a Figure 6 commitment payload.
func (p figure6CommitmentPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 6 commitment payload with limits.
func (p figure6CommitmentPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 6 commitment payload.
func (p *figure6CommitmentPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 6 commitment payload with limits.
func (p *figure6CommitmentPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 6 commitment payload.
func (p figure6CommitmentPayload) Validate() error {
	if len(p.Commitment) != sha256.Size || len(p.ChainCodeCommit) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid Figure 6 commitment fixed-width field")
	}
	return nil
}

type figure6RevealPayload struct {
	Rho               []byte `wire:"1,bytes,len=32"`
	PublicShare       []byte `wire:"2,bytes,max_bytes=point"`
	SchnorrCommitment []byte `wire:"3,bytes,max_bytes=point"`
	Decommitment      []byte `wire:"4,bytes,len=32"`
	PlanHash          []byte `wire:"5,bytes,len=32"`
}

// WireType returns the Figure 6 reveal wire type.
func (figure6RevealPayload) WireType() string { return figure6RevealPayloadWireType }

// WireVersion returns the Figure 6 reveal wire version.
func (figure6RevealPayload) WireVersion() uint16 { return figure6PayloadWireVersion }

// MarshalBinary encodes a Figure 6 reveal payload.
func (p figure6RevealPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 6 reveal payload with limits.
func (p figure6RevealPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 6 reveal payload.
func (p *figure6RevealPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 6 reveal payload with limits.
func (p *figure6RevealPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 6 reveal payload.
func (p figure6RevealPayload) Validate() error {
	if len(p.Rho) != sha256.Size || len(p.Decommitment) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid Figure 6 reveal fixed-width field")
	}
	if _, err := secp.PointFromBytes(p.PublicShare); err != nil {
		return fmt.Errorf("invalid Figure 6 public share: %w", err)
	}
	if _, err := secp.PointFromBytes(p.SchnorrCommitment); err != nil {
		return fmt.Errorf("invalid Figure 6 Schnorr commitment: %w", err)
	}
	return nil
}

func cloneFigure6Reveal(in *figure6RevealPayload) *figure6RevealPayload {
	if in == nil {
		return nil
	}
	return &figure6RevealPayload{
		Rho: bytes.Clone(in.Rho), PublicShare: bytes.Clone(in.PublicShare),
		SchnorrCommitment: bytes.Clone(in.SchnorrCommitment), Decommitment: bytes.Clone(in.Decommitment),
		PlanHash: bytes.Clone(in.PlanHash),
	}
}

type figure6ProofPayload struct {
	Proof    *schnorr.Proof `wire:"1,custom,max_bytes=zk_proof"`
	Rho      tss.SessionID  `wire:"2,bytes,len=32"`
	PlanHash []byte         `wire:"3,bytes,len=32"`
}

// WireType returns the Figure 6 proof wire type.
func (figure6ProofPayload) WireType() string { return figure6ProofPayloadWireType }

// WireVersion returns the Figure 6 proof wire version.
func (figure6ProofPayload) WireVersion() uint16 { return figure6PayloadWireVersion }

// MarshalBinary encodes a Figure 6 proof payload.
func (p figure6ProofPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 6 proof payload with limits.
func (p figure6ProofPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 6 proof payload.
func (p *figure6ProofPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 6 proof payload with limits.
func (p *figure6ProofPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 6 proof payload.
func (p figure6ProofPayload) Validate() error {
	if p.Proof == nil {
		return errors.New("nil Figure 6 Schnorr proof")
	}
	if err := p.Proof.Validate(); err != nil {
		return err
	}
	if !p.Rho.Valid() || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid Figure 6 proof binding")
	}
	return nil
}
