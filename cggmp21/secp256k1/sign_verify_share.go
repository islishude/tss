package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const (
	signVerifyShareWireType                  = "cggmp21.secp256k1.sign-verify-share"
	signVerifyShareWireVersion        uint16 = 1
	signVerifyShareRecordFixedBytes          = 2 + 4*(2+4) + 4
	signVerifyShareEnvelopeFixedBytes        = 4 + 2 + len(signVerifyShareWireType) + 2
)

// WireType returns the canonical wire type identifier for SignVerifyShare.
func (SignVerifyShare) WireType() string { return signVerifyShareWireType }

// WireVersion returns the wire format version for SignVerifyShare.
func (SignVerifyShare) WireVersion() uint16 { return signVerifyShareWireVersion }

// MarshalBinary encodes the verification share using canonical TLV wire format.
func (s SignVerifyShare) MarshalBinary() ([]byte, error) {
	return s.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the verification share with explicit limits.
func (s SignVerifyShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := s.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	raw, err := wire.Marshal(s, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	if len(raw) > limits.SignPrep.MaxVerifyShareBytes {
		return nil, fmt.Errorf("sign verify share too large: %d > %d", len(raw), limits.SignPrep.MaxVerifyShareBytes)
	}
	return raw, nil
}

// UnmarshalBinary decodes a canonical verification share.
func (s *SignVerifyShare) UnmarshalBinary(in []byte) error {
	return s.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical verification share with limits.
func (s *SignVerifyShare) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if s == nil {
		return errors.New("nil sign verify share")
	}
	if len(in) == 0 {
		return errors.New("empty sign verify share")
	}
	if len(in) > limits.SignPrep.MaxVerifyShareBytes {
		return fmt.Errorf("sign verify share too large: %d > %d", len(in), limits.SignPrep.MaxVerifyShareBytes)
	}
	var decoded SignVerifyShare
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.SignPrep.MaxVerifyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*s = decoded
	return nil
}

// Validate checks the verification share's structural invariants.
func (s SignVerifyShare) Validate() error {
	if s.Party == tss.BroadcastPartyId {
		return errors.New("sign verify share: zero party")
	}
	if _, err := secp.PointFromBytes(s.KPoint); err != nil {
		return fmt.Errorf("sign verify share: invalid KPoint: %w", err)
	}
	if _, err := secp.PointFromBytes(s.ChiPoint); err != nil {
		return fmt.Errorf("sign verify share: invalid ChiPoint: %w", err)
	}
	if len(s.Proof) == 0 {
		return errors.New("sign verify share: empty proof")
	}
	return nil
}

// ValidateWithLimits checks the verification share with resource limits.
func (s SignVerifyShare) ValidateWithLimits(limits Limits) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if len(s.KPoint) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("sign verify share KPoint too large: %d > %d", len(s.KPoint), limits.Curve.MaxPointBytes)
	}
	if len(s.ChiPoint) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("sign verify share ChiPoint too large: %d > %d", len(s.ChiPoint), limits.Curve.MaxPointBytes)
	}
	if len(s.Proof) > limits.SignPrep.MaxProofBytes {
		return fmt.Errorf("sign verify share proof too large: %d > %d", len(s.Proof), limits.SignPrep.MaxProofBytes)
	}
	if size := signVerifyShareEnvelopeFixedBytes + signVerifyShareRecordSize(s); size > limits.SignPrep.MaxVerifyShareBytes {
		return fmt.Errorf("sign verify share too large: %d > %d", size, limits.SignPrep.MaxVerifyShareBytes)
	}
	return nil
}

func signVerifyShareRecordSize(s SignVerifyShare) int {
	return signVerifyShareRecordFixedBytes + len(s.KPoint) + len(s.ChiPoint) + len(s.Proof)
}
