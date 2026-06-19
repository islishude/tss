package ed25519

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const verificationShareWireType = "frost.ed25519.verification-share"

const verificationShareWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for VerificationShare.
func (VerificationShare) WireType() string { return verificationShareWireType }

// WireVersion returns the wire format version for VerificationShare.
func (VerificationShare) WireVersion() uint16 { return verificationShareWireVersion }

// MarshalBinary encodes the verification share using canonical TLV.
func (v VerificationShare) MarshalBinary() ([]byte, error) {
	return v.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the verification share with explicit limits.
func (v VerificationShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := v.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return wire.Marshal(v, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes a canonical verification share.
func (v *VerificationShare) UnmarshalBinary(in []byte) error {
	return v.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical verification share with limits.
func (v *VerificationShare) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if v == nil {
		return errors.New("nil verification share")
	}
	var decoded VerificationShare
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*v = decoded.Clone()
	return nil
}

// Validate checks the verification share's structural invariants.
func (v VerificationShare) Validate() error {
	if v.Party == tss.BroadcastPartyId {
		return errors.New("verification share: zero party")
	}
	if err := v.PublicKey.Validate(); err != nil {
		return fmt.Errorf("verification share: invalid public key: %w", err)
	}
	return nil
}

// ValidateWithLimits checks the verification share with resource limits.
func (v VerificationShare) ValidateWithLimits(limits Limits) error {
	publicKey := v.PublicKey.Bytes()
	if len(publicKey) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("verification share public key too large: %d > %d", len(publicKey), limits.Curve.MaxPointBytes)
	}
	return v.Validate()
}
