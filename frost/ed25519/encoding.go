package ed25519

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"

	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType    = "frost.ed25519.keyshare"
	keyShareWireVersion = 1
)

// keyShareWire is the wire DTO for KeyShare.
type keyShareWire struct {
	Party                tss.PartyID           `wire:"1,u32"`
	Threshold            int                   `wire:"2,u32"`
	Parties              tss.PartySet          `wire:"3,u32list"`
	PublicKey            []byte                `wire:"4,bytes,max_bytes=point"`
	Secret               *secret.Scalar        `wire:"5,custom,len=32"`
	GroupCommitments     [][]byte              `wire:"6,byteslist,max_bytes=point,max_items=threshold"`
	VerificationShares   []VerificationShare   `wire:"7,recordlist,max_items=parties"`
	KeygenTranscriptHash []byte                `wire:"8,bytes"`
	ChainCode            []byte                `wire:"9,bytes"`
	KeygenSessionID      []byte                `wire:"10,bytes,len=32"`
	KeygenConfirmations  []*KeygenConfirmation `wire:"11,recordlist,max_items=parties"`
	PlanHash             []byte                `wire:"12,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return keyShareWireVersion }

func encodeKeyShareWire(k *KeyShare) (*keyShareWire, error) {
	return &keyShareWire{
		Party:                k.state.party,
		Threshold:            k.state.threshold,
		Parties:              k.state.parties,
		PublicKey:            k.state.publicKey,
		Secret:               k.state.secret,
		GroupCommitments:     k.state.groupCommitments,
		VerificationShares:   k.state.verificationShares,
		KeygenTranscriptHash: k.state.keygenTranscriptHash,
		ChainCode:            k.state.chainCode,
		KeygenSessionID:      k.state.keygenSessionID[:],
		KeygenConfirmations:  k.state.keygenConfirmations,
		PlanHash:             k.state.planHash,
	}, nil
}

func decodeKeyShareWire(w *keyShareWire) (*keyShareState, error) {
	sid, err := tss.SessionIDFromBytes(w.KeygenSessionID)
	if err != nil {
		return nil, fmt.Errorf("keygen session id: %w", err)
	}
	if _, err := edScalarFromSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	return &keyShareState{
		party:                w.Party,
		threshold:            w.Threshold,
		parties:              w.Parties,
		publicKey:            w.PublicKey,
		chainCode:            w.ChainCode,
		secret:               w.Secret,
		groupCommitments:     w.GroupCommitments,
		verificationShares:   w.VerificationShares,
		keygenSessionID:      sid,
		keygenTranscriptHash: w.KeygenTranscriptHash,
		planHash:             w.PlanHash,
		keygenConfirmations:  w.KeygenConfirmations,
	}, nil
}

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	return wire.Marshal(k, wire.WithFieldLimitsForMarshal(DefaultLimits().fieldLimits()))
}

// WireType returns the canonical wire type identifier for KeyShare.
func (*KeyShare) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for KeyShare.
func (*KeyShare) WireVersion() uint16 { return keyShareWireVersion }

// MarshalWireMessage encodes KeyShare through its private wire DTO.
func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	w, err := encodeKeyShareWire(k)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(w, opts...)
}

// UnmarshalWireMessage decodes KeyShare through its private wire DTO.
func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var w keyShareWire
	if err := wire.Unmarshal(in, &w, opts...); err != nil {
		return err
	}
	state, err := decodeKeyShareWire(&w)
	if err != nil {
		return err
	}
	k.state = state
	return nil
}

// ValidateWithLimits checks KeyShare against explicit local resource limits.
func (k *KeyShare) ValidateWithLimits(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if k.state.threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.state.parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("parties too large: %d > %d", len(k.state.parties), limits.Threshold.MaxParties)
	}
	if len(k.state.groupCommitments) > limits.Threshold.MaxThreshold {
		return fmt.Errorf("group commitments too large: %d > %d", len(k.state.groupCommitments), limits.Threshold.MaxThreshold)
	}
	for i, c := range k.state.groupCommitments {
		if len(c) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("group commitment %d too large: %d > %d", i, len(c), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.state.verificationShares) > limits.Threshold.MaxParties {
		return fmt.Errorf("verification shares too large: %d > %d", len(k.state.verificationShares), limits.Threshold.MaxParties)
	}
	for i, s := range k.state.verificationShares {
		if len(s.PublicKey) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("verification share %d too large: %d > %d", i, len(s.PublicKey), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.state.keygenConfirmations) > limits.Threshold.MaxParties {
		return fmt.Errorf("keygen confirmations too large: %d > %d", len(k.state.keygenConfirmations), limits.Threshold.MaxParties)
	}
	return k.ValidateConsistency()
}
