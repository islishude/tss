package ed25519

import (
	"crypto/sha256"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

const (
	keygenCommitmentsPayloadWireType  = "frost.ed25519.payload.keygen.commitments"
	keygenSharePayloadWireType        = "frost.ed25519.payload.keygen.share"
	nonceCommitmentPayloadWireType    = "frost.ed25519.payload.sign.commitment"
	signPartialPayloadWireType        = "frost.ed25519.payload.sign.partial"
	reshareCommitmentsPayloadWireType = "frost.ed25519.payload.reshare.commitments"
	reshareSharePayloadWireType       = "frost.ed25519.payload.reshare.share"
)

func marshalKeygenCommitmentsPayloadWithLimits(p keygenCommitmentsPayload, limits Limits) ([]byte, error) {
	return p.MarshalBinaryWithLimits(limits)
}

// MarshalBinary encodes the keygen commitments payload.
func (p keygenCommitmentsPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the keygen commitments payload with limits.
func (p keygenCommitmentsPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes the keygen commitments payload.
func (p *keygenCommitmentsPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the keygen commitments payload with limits.
func (p *keygenCommitmentsPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded keygenCommitmentsPayload
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the keygen commitments payload structure.
func (p keygenCommitmentsPayload) Validate() error {
	if len(p.ChainCodeCommit) != 32 {
		return fmt.Errorf("chain code commit must be 32 bytes, got %d", len(p.ChainCodeCommit))
	}
	if len(p.PlanHash) != sha256.Size {
		return fmt.Errorf("keygen commitments plan hash must be 32 bytes")
	}
	if err := p.Commitments.Validate(); err != nil {
		return fmt.Errorf("keygen commitments: %w", err)
	}
	if p.Proof == nil {
		return fmt.Errorf("keygen commitments: missing constant-term proof")
	}
	if err := p.Proof.Validate(); err != nil {
		return fmt.Errorf("keygen commitments proof: %w", err)
	}
	return nil
}

func marshalKeygenSharePayloadWithLimits(p keygenSharePayload, limits Limits) ([]byte, error) {
	return p.MarshalBinaryWithLimits(limits)
}

// MarshalBinary encodes the keygen share payload.
func (p keygenSharePayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the keygen share payload with limits.
func (p keygenSharePayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes the keygen share payload.
func (p *keygenSharePayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the keygen share payload with limits.
func (p *keygenSharePayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded keygenSharePayload
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the keygen share payload structure.
func (p keygenSharePayload) Validate() error {
	if err := validateEdSecretScalar(p.Share); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return fmt.Errorf("keygen share plan hash must be 32 bytes")
	}
	return nil
}

func marshalNonceCommitmentPayloadWithLimits(p nonceCommitment, limits Limits) ([]byte, error) {
	return p.MarshalBinaryWithLimits(limits)
}

// MarshalBinary encodes the nonce commitment payload.
func (p nonceCommitment) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the nonce commitment payload with limits.
func (p nonceCommitment) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes the nonce commitment payload.
func (p *nonceCommitment) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the nonce commitment payload with limits.
func (p *nonceCommitment) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded nonceCommitment
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the nonce commitment payload structure.
func (p nonceCommitment) Validate() error {
	if _, err := p.D.MarshalWireValue(); err != nil {
		return err
	}
	if _, err := p.E.MarshalWireValue(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return fmt.Errorf("nonce commitment plan hash must be 32 bytes")
	}
	return nil
}

func marshalSignPartialPayloadWithLimits(p signPartialPayload, limits Limits) ([]byte, error) {
	return p.MarshalBinaryWithLimits(limits)
}

// MarshalBinary encodes the partial signature payload.
func (p signPartialPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the partial signature payload with limits.
func (p signPartialPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes the partial signature payload.
func (p *signPartialPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the partial signature payload with limits.
func (p *signPartialPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded signPartialPayload
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the partial signature payload structure.
func (p signPartialPayload) Validate() error {
	if _, err := p.Z.MarshalWireValue(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return fmt.Errorf("sign partial plan hash must be 32 bytes")
	}
	return nil
}

func marshalReshareCommitmentsPayloadWithLimits(p reshareCommitmentsPayload, limits Limits) ([]byte, error) {
	return p.MarshalBinaryWithLimits(limits)
}

// MarshalBinary encodes the reshare commitments payload.
func (p reshareCommitmentsPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the reshare commitments payload with limits.
func (p reshareCommitmentsPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes the reshare commitments payload.
func (p *reshareCommitmentsPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the reshare commitments payload with limits.
func (p *reshareCommitmentsPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded reshareCommitmentsPayload
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the reshare commitments payload structure.
func (p reshareCommitmentsPayload) Validate() error {
	if len(p.PlanHash) != sha256.Size {
		return fmt.Errorf("reshare commitments plan hash must be 32 bytes")
	}
	if err := p.Commitments.Validate(); err != nil {
		return fmt.Errorf("reshare commitments: %w", err)
	}
	return nil
}

func marshalReshareSharePayloadWithLimits(p reshareSharePayload, limits Limits) ([]byte, error) {
	return p.MarshalBinaryWithLimits(limits)
}

// MarshalBinary encodes the reshare share payload.
func (p reshareSharePayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the reshare share payload with limits.
func (p reshareSharePayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes the reshare share payload.
func (p *reshareSharePayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the reshare share payload with limits.
func (p *reshareSharePayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded reshareSharePayload
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the reshare share payload structure.
func (p reshareSharePayload) Validate() error {
	if err := validateEdSecretScalar(p.Share); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return fmt.Errorf("reshare share plan hash must be 32 bytes")
	}
	return nil
}
