package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const keygenConfirmationWireVersion = 1

const keygenConfirmationWireType = "cggmp21.secp256k1.keygen-confirmation"

// KeygenConfirmation is a post-keygen consistency artifact. Each party produces
// one after keygen completes and exchanges it with all other parties. If any
// party's confirmation disagrees on the global transcript (public key, party set,
// transcript hash, or commitments hash), the transport may have equivocated and
// the resulting key shares must not be used.
type KeygenConfirmation struct {
	SessionID       tss.SessionID `wire:"1,bytes,len=32"`
	Sender          tss.PartyID   `wire:"2,u32"`
	Threshold       int           `wire:"3,u32"`
	Parties         tss.PartySet  `wire:"4,u32list,max_items=parties"`
	PublicKey       []byte        `wire:"5,bytes,max_bytes=point"`
	TranscriptHash  []byte        `wire:"6,bytes,len=32"`
	CommitmentsHash []byte        `wire:"7,bytes,len=32"`
	ChainCode       []byte        `wire:"8,bytes,len=32"`
	PlanHash        []byte        `wire:"9,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for KeygenConfirmation.
func (KeygenConfirmation) WireType() string { return keygenConfirmationWireType }

// WireVersion returns the wire format version for KeygenConfirmation.
func (KeygenConfirmation) WireVersion() uint16 { return keygenConfirmationWireVersion }

// Clone returns a deep copy of the confirmation.
func (c *KeygenConfirmation) Clone() *KeygenConfirmation {
	if c == nil {
		return nil
	}
	return &KeygenConfirmation{
		SessionID:       c.SessionID,
		Sender:          c.Sender,
		Threshold:       c.Threshold,
		Parties:         slices.Clone(c.Parties),
		PublicKey:       slices.Clone(c.PublicKey),
		TranscriptHash:  slices.Clone(c.TranscriptHash),
		CommitmentsHash: slices.Clone(c.CommitmentsHash),
		ChainCode:       slices.Clone(c.ChainCode),
		PlanHash:        slices.Clone(c.PlanHash),
	}
}

// NewConfirmation constructs a confirmation message from the local key share.
func (k *KeyShare) NewConfirmation() (*KeygenConfirmation, error) {
	return k.NewConfirmationWithLimits(DefaultLimits())
}

// NewConfirmationWithLimits constructs a confirmation using explicit local
// validation limits.
func (k *KeyShare) NewConfirmationWithLimits(limits Limits) (*KeygenConfirmation, error) {
	if err := k.validateWithoutConfirmations(limits); err != nil {
		return nil, fmt.Errorf("cannot build keygen confirmation: %w", err)
	}
	return k.keygenConfirmationReferenceUnchecked()
}

func (k *KeyShare) keygenConfirmationReferenceUnchecked() (*KeygenConfirmation, error) {
	if k == nil {
		return nil, errors.New("nil key share")
	}
	commitmentsHash, err := keygenCommitmentsHash(k.state.GroupCommitments)
	if err != nil {
		return nil, err
	}
	return &KeygenConfirmation{
		SessionID:       k.state.PaillierProofSessionID,
		Sender:          k.state.Party,
		Threshold:       k.state.Threshold,
		Parties:         slices.Clone(k.state.Parties),
		PublicKey:       slices.Clone(k.state.PublicKey),
		TranscriptHash:  slices.Clone(k.state.KeygenTranscriptHash),
		CommitmentsHash: commitmentsHash,
		ChainCode:       slices.Clone(k.state.ChainCode),
		PlanHash:        slices.Clone(k.state.PlanHash),
	}, nil
}

func newKeygenCommitRevealConfirmation(
	pending *KeyShare,
	localChainCode []byte,
	limits Limits,
) (*KeygenConfirmation, error) {
	if pending == nil {
		return nil, errors.New("nil pending key share")
	}
	reference := cloneKeyShareValue(pending)
	if reference == nil {
		return nil, errors.New("nil pending key share")
	}
	defer reference.Destroy()
	reference.state.ChainCode = bytes.Clone(localChainCode)
	if err := reference.validateWithoutConfirmations(limits); err != nil {
		return nil, fmt.Errorf("cannot build keygen confirmation: %w", err)
	}
	confirmation, err := reference.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return nil, err
	}
	if err := confirmation.Validate(); err != nil {
		clear(confirmation.ChainCode)
		return nil, err
	}
	return confirmation, nil
}

func keygenCommitmentsHash(commitments []*secp.Point) ([]byte, error) {
	commitmentBytes, err := secp.CommitmentPointsBytes(commitments)
	if err != nil {
		return nil, err
	}
	t := transcript.New(keygenCommitmentsHashLabel)
	t.AppendBytesList("group_commitments", commitmentBytes)
	return t.Sum(), nil
}

func keygenConfirmationSetHash(confirmations []*KeygenConfirmation) []byte {
	t := transcript.New(keygenConfirmationWireType)
	for _, confirmation := range confirmations {
		encoded, err := confirmation.MarshalBinary()
		if err != nil {
			return nil
		}
		t.AppendBytes("confirmation", encoded)
	}
	return t.Sum()
}

// Validate performs structural checks on the confirmation.
func (c KeygenConfirmation) Validate() error {
	if c.Sender == tss.BroadcastPartyId {
		return errors.New("keygen confirmation: zero sender")
	}
	if c.Threshold < 1 {
		return errors.New("keygen confirmation: threshold < 1")
	}
	if len(c.Parties) == 0 {
		return errors.New("keygen confirmation: empty party set")
	}
	if len(c.PublicKey) == 0 {
		return errors.New("keygen confirmation: empty public key")
	}
	if len(c.TranscriptHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid transcript hash length")
	}
	if len(c.CommitmentsHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid commitments hash length")
	}
	if len(c.ChainCode) != bip32util.ChainCodeSize {
		return errors.New("keygen confirmation: chain code must be 32 bytes")
	}
	if len(c.PlanHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid plan hash length")
	}
	if err := wire.ValidateStrictSortedIDs(c.Parties); err != nil {
		return fmt.Errorf("keygen confirmation: %w", err)
	}
	if !slices.Contains(c.Parties, c.Sender) {
		return errors.New("keygen confirmation: sender not in party set")
	}
	return nil
}

// MarshalBinary encodes the confirmation using the object-level wire codec.
// wire.Marshal calls Validate via the Validator interface.
func (c KeygenConfirmation) MarshalBinary() ([]byte, error) {
	return c.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the confirmation with explicit local limits.
func (c KeygenConfirmation) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return wire.Marshal(c, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes a canonical TLV keygen confirmation.
func (c *KeygenConfirmation) UnmarshalBinary(in []byte) error {
	return c.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical TLV keygen confirmation with
// explicit local limits.
func (c *KeygenConfirmation) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded KeygenConfirmation
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.Payload.MaxMessageBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*c = decoded
	return nil
}
