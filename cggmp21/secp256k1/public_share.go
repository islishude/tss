package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	verificationShareWireType                 = "cggmp21.secp256k1.verification-share"
	paillierPublicShareWireType               = "cggmp21.secp256k1.paillier-public-share"
	ringPedersenPublicShareWireType           = "cggmp21.secp256k1.ring-pedersen-public-share"
	verificationShareWireVersion       uint16 = 1
	paillierPublicShareWireVersion     uint16 = 1
	ringPedersenPublicShareWireVersion uint16 = 1
)

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
	*v = decoded
	return nil
}

// Validate checks the verification share's structural invariants.
func (v VerificationShare) Validate() error {
	if v.Party == tss.BroadcastPartyId {
		return errors.New("verification share: zero party")
	}
	if _, err := secp.PointFromBytes(v.PublicKey); err != nil {
		return fmt.Errorf("verification share: invalid public key: %w", err)
	}
	return nil
}

// ValidateWithLimits checks the verification share with resource limits.
func (v VerificationShare) ValidateWithLimits(limits Limits) error {
	if len(v.PublicKey) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("verification share public key too large: %d > %d", len(v.PublicKey), limits.Curve.MaxPointBytes)
	}
	return v.Validate()
}

// WireType returns the canonical wire type identifier for PaillierPublicShare.
func (PaillierPublicShare) WireType() string { return paillierPublicShareWireType }

// WireVersion returns the wire format version for PaillierPublicShare.
func (PaillierPublicShare) WireVersion() uint16 { return paillierPublicShareWireVersion }

// MarshalBinary encodes the Paillier public share using canonical TLV.
func (p PaillierPublicShare) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the Paillier public share with explicit limits.
func (p PaillierPublicShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes a canonical Paillier public share.
func (p *PaillierPublicShare) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical Paillier public share with limits.
func (p *PaillierPublicShare) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if p == nil {
		return errors.New("nil Paillier public share")
	}
	var decoded PaillierPublicShare
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the Paillier public share's structural invariants.
func (p PaillierPublicShare) Validate() error {
	return p.validateWithMaxModulusBits(maxEncodedBits(len(p.PublicKey)))
}

// ValidateWithLimits checks the Paillier public share with resource limits.
func (p PaillierPublicShare) ValidateWithLimits(limits Limits) error {
	if len(p.PublicKey) > limits.Paillier.MaxPublicKeyBytes {
		return fmt.Errorf("paillier public share key too large: %d > %d", len(p.PublicKey), limits.Paillier.MaxPublicKeyBytes)
	}
	if len(p.Proof) > limits.ZK.MaxProofBytes {
		return fmt.Errorf("paillier public share proof too large: %d > %d", len(p.Proof), limits.ZK.MaxProofBytes)
	}
	return p.validateWithMaxModulusBits(limits.Paillier.MaxModulusBits)
}

func (p PaillierPublicShare) validateWithMaxModulusBits(maxBits int) error {
	if p.Party == tss.BroadcastPartyId {
		return errors.New("paillier public share: zero party")
	}
	if len(p.PublicKey) == 0 {
		return errors.New("paillier public share: empty public key")
	}
	if _, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PublicKey, maxBits); err != nil {
		return fmt.Errorf("paillier public share: invalid public key: %w", err)
	}
	if len(p.Proof) == 0 {
		return errors.New("paillier public share: empty proof")
	}
	if _, err := tss.DecodeBinary[zkpai.ModulusProof](p.Proof); err != nil {
		return fmt.Errorf("paillier public share: invalid proof: %w", err)
	}
	return nil
}

// WireType returns the canonical wire type identifier for RingPedersenPublicShare.
func (RingPedersenPublicShare) WireType() string { return ringPedersenPublicShareWireType }

// WireVersion returns the wire format version for RingPedersenPublicShare.
func (RingPedersenPublicShare) WireVersion() uint16 {
	return ringPedersenPublicShareWireVersion
}

// MarshalBinary encodes the Ring-Pedersen public share using canonical TLV.
func (r RingPedersenPublicShare) MarshalBinary() ([]byte, error) {
	return r.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the Ring-Pedersen public share with explicit limits.
func (r RingPedersenPublicShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := r.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return wire.Marshal(r, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes a canonical Ring-Pedersen public share.
func (r *RingPedersenPublicShare) UnmarshalBinary(in []byte) error {
	return r.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical Ring-Pedersen public share with limits.
func (r *RingPedersenPublicShare) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if r == nil {
		return errors.New("nil Ring-Pedersen public share")
	}
	var decoded RingPedersenPublicShare
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*r = decoded
	return nil
}

// Validate checks the Ring-Pedersen public share's structural invariants.
func (r RingPedersenPublicShare) Validate() error {
	return r.validateWithMaxModulusBits(maxEncodedBits(len(r.Params)))
}

// ValidateWithLimits checks the Ring-Pedersen public share with resource limits.
func (r RingPedersenPublicShare) ValidateWithLimits(limits Limits) error {
	if len(r.Params) > limits.Paillier.MaxRingPedersenBytes {
		return fmt.Errorf("Ring-Pedersen public share parameters too large: %d > %d", len(r.Params), limits.Paillier.MaxRingPedersenBytes)
	}
	if len(r.Proof) > limits.Paillier.MaxProofBytes {
		return fmt.Errorf("Ring-Pedersen public share proof too large: %d > %d", len(r.Proof), limits.Paillier.MaxProofBytes)
	}
	return r.validateWithMaxModulusBits(limits.Paillier.MaxModulusBits)
}

func (r RingPedersenPublicShare) validateWithMaxModulusBits(maxBits int) error {
	if r.Party == tss.BroadcastPartyId {
		return errors.New("Ring-Pedersen public share: zero party")
	}
	if len(r.Params) == 0 {
		return errors.New("Ring-Pedersen public share: empty parameters")
	}
	if _, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(r.Params, maxBits); err != nil {
		return fmt.Errorf("Ring-Pedersen public share: invalid parameters: %w", err)
	}
	if len(r.Proof) == 0 {
		return errors.New("Ring-Pedersen public share: empty proof")
	}
	if _, err := tss.DecodeBinary[zkpai.RingPedersenProof](r.Proof); err != nil {
		return fmt.Errorf("Ring-Pedersen public share: invalid proof: %w", err)
	}
	return nil
}

func maxEncodedBits(size int) int {
	if size <= 0 {
		return 1
	}
	return size * 8
}
