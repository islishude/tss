package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType           = "cggmp21.secp256k1.keyshare"
	presignWireType            = "cggmp21.secp256k1.presign"
	keyShareWireVersion uint16 = 1
	presignWireVersion  uint16 = 1
)

// WireType returns the canonical wire type identifier for keyShareState.
func (*keyShareState) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareState.
func (*keyShareState) WireVersion() uint16 { return keyShareWireVersion }

// MarshalJSON rejects JSON encoding of secret-bearing key share state.
func (*keyShareState) MarshalJSON() ([]byte, error) {
	return nil, errors.New("keyShareState contains secret material; use MarshalBinary")
}

func keyShareCodecLimits(fieldLimits wire.FieldLimits) (Limits, error) {
	limits := DefaultLimits()
	if fieldLimits == nil {
		return limits, nil
	}
	required := []struct {
		name string
		dst  *int
	}{
		{name: "scalar", dst: &limits.Curve.MaxScalarBytes},
		{name: "point", dst: &limits.Curve.MaxPointBytes},
		{name: "parties", dst: &limits.Threshold.MaxParties},
		{name: "threshold", dst: &limits.Threshold.MaxThreshold},
		{name: "paillier_modulus_bits", dst: &limits.Paillier.MaxModulusBits},
		{name: "paillier_public_key", dst: &limits.Paillier.MaxPublicKeyBytes},
		{name: "paillier_private_key", dst: &limits.Paillier.MaxPrivateKeyBytes},
		{name: "paillier_ciphertext", dst: &limits.Paillier.MaxCiphertextBytes},
		{name: "paillier_proof", dst: &limits.Paillier.MaxProofBytes},
		{name: "ring_pedersen_params", dst: &limits.Paillier.MaxRingPedersenBytes},
		{name: "zk_proof", dst: &limits.ZK.MaxProofBytes},
	}
	for _, item := range required {
		value, ok := fieldLimits[item.name]
		if !ok {
			return Limits{}, fmt.Errorf("wire: missing field limit %q for key share state", item.name)
		}
		if value <= 0 {
			return Limits{}, fmt.Errorf("wire: field limit %q for key share state must be positive", item.name)
		}
		*item.dst = value
	}
	return limits, nil
}

func (state *keyShareState) checkPartyDataKeys() error {
	if len(state.PartyData) != len(state.Parties) {
		return fmt.Errorf("party data count %d != party count %d", len(state.PartyData), len(state.Parties))
	}
	for _, id := range state.Parties {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		data, ok := state.PartyData[id]
		if !ok {
			return fmt.Errorf("missing party data for participant %d", id)
		}
		if data.KeygenConfirmation != nil && data.KeygenConfirmation.Sender != id {
			return fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.KeygenConfirmation.Sender, id)
		}
	}
	for id := range state.PartyData {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		if !tss.ContainsParty(state.Parties, id) {
			return fmt.Errorf("party data for non-participant %d", id)
		}
	}
	return nil
}

// WireType returns the canonical wire type identifier for KeyShare.
func (*KeyShare) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for KeyShare.
func (*KeyShare) WireVersion() uint16 { return keyShareWireVersion }

// MarshalWireMessage encodes KeyShare through its private state codec.
func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	resolved := wire.ResolveMarshalOptions(opts...)
	limits, err := keyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	return k.marshalWireMessageWithLimits(limits, opts...)
}

func (k *KeyShare) marshalWireMessageWithLimits(limits Limits, opts ...wire.MarshalOption) ([]byte, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	if err := k.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	opts = append(opts, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	return wire.Marshal(k.state, opts...)
}

// UnmarshalWireMessage decodes KeyShare through its private state codec.
func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	resolved := wire.ResolveUnmarshalOptions(opts...)
	limits, err := keyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return err
	}
	return k.unmarshalWireMessageWithLimits(in, limits, opts...)
}

func (k *KeyShare) unmarshalWireMessageWithLimits(in []byte, limits Limits, opts ...wire.UnmarshalOption) error {
	if k == nil {
		return errors.New("nil key share")
	}
	opts = append(opts, wire.WithFieldLimits(limits.fieldLimits()))
	var state keyShareState
	if err := wire.Unmarshal(in, &state, opts...); err != nil {
		return err
	}
	decoded := &KeyShare{state: &state}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		decoded.Destroy()
		return err
	}
	k.state = &state
	return nil
}

// Clone returns an independently owned deep copy of the key share.
//
// The clone contains secret material and must be destroyed separately when it is
// no longer needed. Destroying the clone does not destroy the original, and
// destroying the original does not destroy the clone.
func (k *KeyShare) Clone() *KeyShare {
	return cloneKeyShareValue(k)
}

// WireType returns the canonical wire type identifier for presignState.
func (*presignState) WireType() string { return presignWireType }

// WireVersion returns the wire format version for presignState.
func (*presignState) WireVersion() uint16 { return presignWireVersion }

// BeforeMarshalWire rejects every state except an unclaimed available record.
// It is deliberately side-effect free: persistence must not consume a
// presign before the lifecycle store atomically claims it with an attempt.
func (state *presignState) BeforeMarshalWire() error {
	if state == nil {
		return errors.New("nil presign state")
	}
	if state.Consumed.Bool == nil || state.attempt == nil {
		return errors.New("presign lifecycle state unavailable")
	}
	if state.Consumed.Load() || !state.attempt.available() {
		return errors.New("only available presigns can be serialized")
	}
	return nil
}

// AfterUnmarshalWire restores a persisted record to the available state. The
// consumed marker is runtime-only and is intentionally absent from the wire.
func (state *presignState) AfterUnmarshalWire() error {
	if state == nil {
		return errors.New("nil presign state")
	}
	state.Consumed = newAtomicBool()
	state.attempt = newPresignAttemptBinding(false)
	return nil
}

// MarshalJSON rejects JSON encoding of secret-bearing presign state.
func (*presignState) MarshalJSON() ([]byte, error) {
	return nil, errors.New("presignState contains secret material; use MarshalBinary")
}

func presignCodecLimits(fieldLimits wire.FieldLimits) (Limits, error) {
	limits := DefaultLimits()
	if fieldLimits == nil {
		return limits, nil
	}
	required := []struct {
		name string
		dst  *int
	}{
		{name: "scalar", dst: &limits.Curve.MaxScalarBytes},
		{name: "point", dst: &limits.Curve.MaxPointBytes},
		{name: "signers", dst: &limits.Threshold.MaxSigners},
		{name: "threshold", dst: &limits.Threshold.MaxThreshold},
	}
	for _, item := range required {
		value, ok := fieldLimits[item.name]
		if !ok {
			return Limits{}, fmt.Errorf("wire: missing field limit %q for presign state", item.name)
		}
		if value <= 0 {
			return Limits{}, fmt.Errorf("wire: field limit %q for presign state must be positive", item.name)
		}
		*item.dst = value
	}
	return limits, nil
}

// WireType returns the canonical wire type identifier for Presign.
func (*Presign) WireType() string { return presignWireType }

// WireVersion returns the wire format version for Presign.
func (*Presign) WireVersion() uint16 { return presignWireVersion }

// MarshalWireMessage encodes Presign through its private state codec.
func (p *Presign) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	resolved := wire.ResolveMarshalOptions(opts...)
	limits, err := presignCodecLimits(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	return p.marshalWireMessageWithLimits(limits, opts...)
}

func (p *Presign) marshalWireMessageWithLimits(limits Limits, opts ...wire.MarshalOption) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil presign")
	}
	if err := p.state.BeforeMarshalWire(); err != nil {
		return nil, err
	}
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	opts = append(opts, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	return wire.Marshal(p.state, opts...)
}

// UnmarshalWireMessage decodes Presign through its private state codec.
func (p *Presign) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	resolved := wire.ResolveUnmarshalOptions(opts...)
	limits, err := presignCodecLimits(resolved.FieldLimits)
	if err != nil {
		return err
	}
	return p.unmarshalWireMessageWithLimits(in, limits, opts...)
}

func (p *Presign) unmarshalWireMessageWithLimits(in []byte, limits Limits, opts ...wire.UnmarshalOption) error {
	if p == nil {
		return errors.New("nil presign")
	}
	opts = append(opts, wire.WithFieldLimits(limits.fieldLimits()))
	var state presignState
	if err := wire.Unmarshal(in, &state, opts...); err != nil {
		return err
	}
	decoded := &Presign{state: &state}
	// A persisted available record is accepted only after replaying every
	// normalized Figure 8 opening and aggregate commitment equation. Structural
	// canonicality alone is not sufficient at this secret-state boundary.
	if err := decoded.ValidateWithLimits(limits); err != nil {
		decoded.Destroy()
		return err
	}
	p.state = &state
	return nil
}
