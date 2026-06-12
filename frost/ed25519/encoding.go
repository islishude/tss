package ed25519

import (
	"fmt"

	"github.com/islishude/tss"

	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const keyShareWireType = "frost.ed25519.keyshare"

// keyShareWire is the wire DTO for KeyShare.
type keyShareWire struct {
	Party                tss.PartyID                    `wire:"1,u32"`
	Threshold            int                            `wire:"2,u32"`
	Parties              []tss.PartyID                  `wire:"3,u32list"`
	PublicKey            []byte                         `wire:"4,bytes,max_bytes=point"`
	Secret               *secret.Scalar                 `wire:"5,custom,len=32"`
	GroupCommitments     [][]byte                       `wire:"6,byteslist,max_bytes=point,max_items=threshold"`
	VerificationShares   []wire.PartyBytes[tss.PartyID] `wire:"7,partybytes,max_bytes=point"`
	KeygenTranscriptHash []byte                         `wire:"8,bytes"`
	ChainCode            []byte                         `wire:"9,bytes"`
	KeygenSessionID      []byte                         `wire:"10,bytes,len=32"`
	KeygenConfirmations  [][]byte                       `wire:"11,byteslist"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return tss.Version }

func (k *KeyShare) toWire() (*keyShareWire, error) {
	shares := make([]wire.PartyBytes[tss.PartyID], len(k.VerificationShares))
	for i, s := range k.VerificationShares {
		shares[i] = wire.PartyBytes[tss.PartyID]{Party: s.Party, Bytes: s.PublicKey}
	}
	return &keyShareWire{
		Party:                k.Party,
		Threshold:            k.Threshold,
		Parties:              k.Parties,
		PublicKey:            k.PublicKey,
		Secret:               k.secret,
		GroupCommitments:     k.GroupCommitments,
		VerificationShares:   shares,
		KeygenTranscriptHash: k.KeygenTranscriptHash,
		ChainCode:            k.ChainCode,
		KeygenSessionID:      k.KeygenSessionID[:],
		KeygenConfirmations:  k.KeygenConfirmations,
	}, nil
}

func (w keyShareWire) toKeyShare() (*KeyShare, error) {
	sid, err := tss.SessionIDFromBytes(w.KeygenSessionID)
	if err != nil {
		return nil, fmt.Errorf("keygen session id: %w", err)
	}
	if _, err := edScalarFromSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	shares := make([]VerificationShare, len(w.VerificationShares))
	for i, s := range w.VerificationShares {
		shares[i] = VerificationShare{Party: s.Party, PublicKey: s.Bytes}
	}
	return &KeyShare{
		Version:              tss.Version,
		Party:                w.Party,
		Threshold:            w.Threshold,
		Parties:              w.Parties,
		PublicKey:            w.PublicKey,
		ChainCode:            w.ChainCode,
		secret:               w.Secret,
		GroupCommitments:     w.GroupCommitments,
		VerificationShares:   shares,
		KeygenSessionID:      sid,
		KeygenTranscriptHash: w.KeygenTranscriptHash,
		KeygenConfirmations:  w.KeygenConfirmations,
	}, nil
}

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	w, err := k.toWire()
	if err != nil {
		return nil, err
	}
	return wire.Marshal(w, wire.WithFieldLimitsForMarshal(DefaultLimits().fieldLimits()))
}

func unmarshalKeyShareWithLimits(in []byte, limits Limits) (*KeyShare, error) {
	var w keyShareWire
	if err := wire.Unmarshal(in, &w,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return nil, err
	}
	k, err := w.toKeyShare()
	if err != nil {
		return nil, err
	}
	if k.Threshold > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", k.Threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.Parties) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("parties too large: %d > %d", len(k.Parties), limits.Threshold.MaxParties)
	}
	if len(k.GroupCommitments) > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("group commitments too large: %d > %d", len(k.GroupCommitments), limits.Threshold.MaxThreshold)
	}
	for i, c := range k.GroupCommitments {
		if len(c) > limits.Curve.MaxPointBytes {
			return nil, fmt.Errorf("group commitment %d too large: %d > %d", i, len(c), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.VerificationShares) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("verification shares too large: %d > %d", len(k.VerificationShares), limits.Threshold.MaxParties)
	}
	for i, s := range k.VerificationShares {
		if len(s.PublicKey) > limits.Curve.MaxPointBytes {
			return nil, fmt.Errorf("verification share %d too large: %d > %d", i, len(s.PublicKey), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.KeygenConfirmations) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("keygen confirmations too large: %d > %d", len(k.KeygenConfirmations), limits.Threshold.MaxParties)
	}
	for i, c := range k.KeygenConfirmations {
		if len(c) > limits.TLV.MaxFieldBytes {
			return nil, fmt.Errorf("keygen confirmation %d too large: %d > %d", i, len(c), limits.TLV.MaxFieldBytes)
		}
	}
	if err := k.ValidateConsistency(); err != nil {
		return nil, err
	}
	return k, nil
}
