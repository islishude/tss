package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

const (
	childDerivationPlanWireType           = "cggmp21.secp256k1.child-derivation-plan"
	childDerivationPlanWireVersion uint16 = 1
)

// WireType returns the canonical child-derivation plan wire type.
func (*childDerivationPlanState) WireType() string { return childDerivationPlanWireType }

// WireVersion returns the canonical child-derivation plan wire version.
func (*childDerivationPlanState) WireVersion() uint16 { return childDerivationPlanWireVersion }

// MarshalBinary returns the canonical plan encoding.
func (p *ChildDerivationPlan) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil child derivation plan")
	}
	return p.MarshalBinaryWithLimits(p.limits)
}

// MarshalBinaryWithLimits returns the canonical plan encoding under limits.
func (p *ChildDerivationPlan) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil child derivation plan")
	}
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	raw, err := wire.Marshal(p.state, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	max := limits.State.MaxSerializedChildDerivationPlanBytes
	if max <= 0 || len(raw) > max {
		return nil, fmt.Errorf("child derivation plan too large: %d > %d", len(raw), max)
	}
	return raw, nil
}

// UnmarshalBinary decodes and validates a canonical child-derivation plan.
func (p *ChildDerivationPlan) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes and validates a canonical plan under
// explicit local resource limits.
func (p *ChildDerivationPlan) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if p == nil {
		return errors.New("nil child derivation plan")
	}
	max := limits.State.MaxSerializedChildDerivationPlanBytes
	if max <= 0 || len(in) == 0 || len(in) > max {
		return fmt.Errorf("invalid child derivation plan size: %d", len(in))
	}
	var state childDerivationPlanState
	if err := wire.Unmarshal(in, &state,
		wire.WithFrameLimits(limits.frameLimits(max)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	decoded := &ChildDerivationPlan{state: &state, limits: limits}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*p = *decoded
	return nil
}
