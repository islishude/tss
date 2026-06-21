package ed25519

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType    = "frost.ed25519.keyshare"
	keyShareWireVersion = 1
)

// WireType returns the canonical wire type identifier for keyShareState.
func (*keyShareState) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareState.
func (*keyShareState) WireVersion() uint16 { return keyShareWireVersion }

// MarshalJSON rejects JSON encoding of secret-bearing key share state.
func (*keyShareState) MarshalJSON() ([]byte, error) {
	return nil, errors.New("keyShareState contains secret material; use MarshalBinary")
}

func frostKeyShareCodecLimits(fieldLimits wire.FieldLimits) (Limits, error) {
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
			return fmt.Errorf(
				"keygen confirmation sender %d does not match party data key %d",
				data.KeygenConfirmation.Sender,
				id,
			)
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

// MarshalWireMessage encodes KeyShare through its reflection-backed private state.
func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	resolved := wire.ResolveMarshalOptions(opts...)
	limits, err := frostKeyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	}
	if err := k.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return wire.Marshal(k.state, opts...)
}

// UnmarshalWireMessage decodes KeyShare through its reflection-backed private state.
func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if k == nil {
		return errors.New("nil key share")
	}
	resolved := wire.ResolveUnmarshalOptions(opts...)
	limits, err := frostKeyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimits(limits.fieldLimits()))
	}
	var state keyShareState
	if err := wire.Unmarshal(in, &state, opts...); err != nil {
		(&KeyShare{state: &state}).Destroy()
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

// ValidateWithLimits checks KeyShare against explicit local resource limits.
func (k *KeyShare) ValidateWithLimits(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if k.state.Threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.Threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.state.Parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("parties too large: %d > %d", len(k.state.Parties), limits.Threshold.MaxParties)
	}
	if k.state.GroupCommitments.Len() > limits.Threshold.MaxThreshold {
		return fmt.Errorf(
			"group commitments too large: %d > %d",
			k.state.GroupCommitments.Len(),
			limits.Threshold.MaxThreshold,
		)
	}
	for i, commitment := range k.state.GroupCommitments.BytesList() {
		if len(commitment) > limits.Curve.MaxPointBytes {
			return fmt.Errorf(
				"group commitment %d too large: %d > %d",
				i,
				len(commitment),
				limits.Curve.MaxPointBytes,
			)
		}
	}
	if len(k.state.PartyData) > limits.Threshold.MaxParties {
		return fmt.Errorf("party data too large: %d > %d", len(k.state.PartyData), limits.Threshold.MaxParties)
	}
	confirmationCount := 0
	for id, data := range k.state.PartyData {
		encoded := data.VerificationShare.Bytes()
		if len(encoded) > limits.Curve.MaxPointBytes {
			return fmt.Errorf(
				"verification share for party %d too large: %d > %d",
				id,
				len(encoded),
				limits.Curve.MaxPointBytes,
			)
		}
		if data.KeygenConfirmation != nil {
			confirmationCount++
		}
	}
	if confirmationCount > limits.Threshold.MaxParties {
		return fmt.Errorf(
			"keygen confirmations too large: %d > %d",
			confirmationCount,
			limits.Threshold.MaxParties,
		)
	}
	return k.ValidateConsistency()
}

// Clone returns an independently owned deep copy of the key share.
//
// The clone contains secret material and must be destroyed separately when it is
// no longer needed. Destroying the clone does not destroy the original, and
// destroying the original does not destroy the clone.
func (k *KeyShare) Clone() *KeyShare {
	return cloneKeyShareValue(k)
}
