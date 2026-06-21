package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

const (
	resharePlanWireType           = "cggmp21.secp256k1.reshare-plan"
	resharePlanWireVersion uint16 = 1
)

// MarshalBinary returns the canonical wire encoding of p.
func (p *ResharePlan) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil reshare plan")
	}
	return p.MarshalBinaryWithLimits(p.limits)
}

// MarshalBinaryWithLimits returns the canonical wire encoding of p using
// explicit local resource limits.
func (p *ResharePlan) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil reshare plan")
	}
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	raw, err := p.MarshalWireMessage(wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	if len(raw) > limits.State.MaxSerializedResharePlanBytes {
		return nil, fmt.Errorf("reshare plan too large: %d > %d", len(raw), limits.State.MaxSerializedResharePlanBytes)
	}
	return raw, nil
}

// UnmarshalBinary decodes and validates a canonical reshare plan.
func (p *ResharePlan) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical reshare plan into the receiver
// using explicit local resource limits.
func (p *ResharePlan) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if p == nil {
		return errors.New("nil reshare plan")
	}
	if len(in) > limits.State.MaxSerializedResharePlanBytes {
		return fmt.Errorf("reshare plan too large: %d > %d", len(in), limits.State.MaxSerializedResharePlanBytes)
	}
	var decoded ResharePlan
	if err := decoded.UnmarshalWireMessage(in,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedResharePlanBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	decoded.limits = limits
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// WireType returns the canonical wire type identifier for ResharePlan.
func (*ResharePlan) WireType() string { return resharePlanWireType }

// WireVersion returns the wire format version for ResharePlan.
func (*ResharePlan) WireVersion() uint16 { return resharePlanWireVersion }

// WireType returns the canonical wire type identifier for resharePlanState.
func (*resharePlanState) WireType() string { return resharePlanWireType }

// WireVersion returns the wire format version for resharePlanState.
func (*resharePlanState) WireVersion() uint16 { return resharePlanWireVersion }

// MarshalWireMessage encodes ResharePlan through its private state codec.
func (p *ResharePlan) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil reshare plan")
	}
	resolved := wire.ResolveMarshalOptions(opts...)
	config, err := resharePlanCodecConfig(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(config.limits.fieldLimits()))
	}
	if err := p.ValidateWithLimits(config.limits); err != nil {
		return nil, err
	}
	return wire.Marshal(p.state, opts...)
}

// UnmarshalWireMessage decodes ResharePlan through its private state codec.
func (p *ResharePlan) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if p == nil {
		return errors.New("nil reshare plan")
	}
	resolved := wire.ResolveUnmarshalOptions(opts...)
	config, err := resharePlanCodecConfig(resolved.FieldLimits)
	if err != nil {
		return err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimits(config.limits.fieldLimits()))
	}
	var state resharePlanState
	if err := wire.Unmarshal(in, &state, opts...); err != nil {
		return err
	}
	decoded := ResharePlan{state: &state, limits: config.limits}
	if err := decoded.ValidateWithLimits(config.limits); err != nil {
		return err
	}
	*p = decoded
	return nil
}

type resharePlanCodecOptions struct {
	limits Limits
}

func resharePlanCodecConfig(fieldLimits wire.FieldLimits) (resharePlanCodecOptions, error) {
	limits := DefaultLimits()
	if fieldLimits == nil {
		return resharePlanCodecOptions{limits: limits}, nil
	}
	required := []struct {
		name string
		dst  *int
	}{
		{name: "point", dst: &limits.Curve.MaxPointBytes},
		{name: "parties", dst: &limits.Threshold.MaxParties},
		{name: "threshold", dst: &limits.Threshold.MaxThreshold},
		{name: "paillier_modulus_bits", dst: &limits.Paillier.MaxModulusBits},
	}
	for _, item := range required {
		value, ok := fieldLimits[item.name]
		if !ok {
			return resharePlanCodecOptions{}, fmt.Errorf("wire: missing field limit %q for reshare plan", item.name)
		}
		if value <= 0 {
			return resharePlanCodecOptions{}, fmt.Errorf("wire: field limit %q for reshare plan must be positive", item.name)
		}
		*item.dst = value
	}
	curveIDBytes, ok := fieldLimits["curve_id"]
	if !ok {
		return resharePlanCodecOptions{}, fmt.Errorf("wire: missing field limit %q for reshare plan", "curve_id")
	}
	if curveIDBytes <= 0 {
		return resharePlanCodecOptions{}, fmt.Errorf("wire: field limit %q for reshare plan must be positive", "curve_id")
	}
	return resharePlanCodecOptions{limits: limits}, nil
}
