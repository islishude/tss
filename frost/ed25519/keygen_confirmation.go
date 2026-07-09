package ed25519

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const keygenConfirmationWireVersion = 1

const keygenConfirmationWireType = "frost.ed25519.keygen-confirmation"

// KeygenConfirmation is a post-keygen consistency artifact.
type KeygenConfirmation struct {
	SessionID       tss.SessionID  `wire:"1,bytes,len=32"`
	Sender          tss.PartyID    `wire:"2,u32"`
	Threshold       int            `wire:"3,u32"`
	Parties         tss.PartySet   `wire:"4,u32list"`
	PublicKey       PublicKeyPoint `wire:"5,custom,len=32"`
	TranscriptHash  []byte         `wire:"6,bytes,len=32"`
	CommitmentsHash []byte         `wire:"7,bytes,len=32"`
	ChainCode       []byte         `wire:"8,bytes,len=32"`
	PlanHash        []byte         `wire:"9,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for KeygenConfirmation.
func (KeygenConfirmation) WireType() string { return keygenConfirmationWireType }

// WireVersion returns the wire format version for KeygenConfirmation.
func (KeygenConfirmation) WireVersion() uint16 { return keygenConfirmationWireVersion }

// NewConfirmation constructs a confirmation message from the local key share.
func (k *KeyShare) NewConfirmation() (*KeygenConfirmation, error) {
	if err := k.validateWithoutConfirmations(); err != nil {
		return nil, fmt.Errorf("cannot build keygen confirmation: %w", err)
	}
	return k.keygenConfirmationReferenceUnchecked()
}

func (k *KeyShare) keygenConfirmationReferenceUnchecked() (*KeygenConfirmation, error) {
	if k == nil {
		return nil, errors.New("nil key share")
	}
	return &KeygenConfirmation{
		SessionID:       k.state.KeygenSessionID,
		Sender:          k.state.Party,
		Threshold:       k.state.Threshold,
		Parties:         slices.Clone(k.state.Parties),
		PublicKey:       k.state.PublicKey.Clone(),
		TranscriptHash:  slices.Clone(k.state.KeygenTranscriptHash),
		CommitmentsHash: keygenGroupCommitmentsHash(k.state.GroupCommitments.BytesList()),
		ChainCode:       slices.Clone(k.state.ChainCode),
		PlanHash:        slices.Clone(k.state.PlanHash),
	}, nil
}

func newFROSTKeygenConfirmation(pending *frostPendingKeyShare) (*KeygenConfirmation, error) {
	if pending == nil {
		return nil, errors.New("nil pending key share")
	}
	return pending.confirmationReference(pending.party, pending.localChainCode)
}

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
		PublicKey:       c.PublicKey.Clone(),
		TranscriptHash:  slices.Clone(c.TranscriptHash),
		CommitmentsHash: slices.Clone(c.CommitmentsHash),
		ChainCode:       slices.Clone(c.ChainCode),
		PlanHash:        slices.Clone(c.PlanHash),
	}
}

// Validate performs structural checks on the confirmation.
func (c KeygenConfirmation) Validate() error {
	if c.Sender == 0 {
		return errors.New("keygen confirmation: zero sender")
	}
	if c.Threshold < 1 {
		return errors.New("keygen confirmation: threshold < 1")
	}
	if len(c.Parties) == 0 {
		return errors.New("keygen confirmation: empty party set")
	}
	if err := c.PublicKey.Validate(); err != nil {
		return fmt.Errorf("keygen confirmation: invalid public key: %w", err)
	}
	if len(c.TranscriptHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid transcript hash length")
	}
	if len(c.CommitmentsHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid commitments hash length")
	}
	if len(c.ChainCode) != 32 {
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
func (c KeygenConfirmation) MarshalBinary() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(c)
}

// UnmarshalBinary decodes a canonical TLV keygen confirmation.
func (c *KeygenConfirmation) UnmarshalBinary(in []byte) error {
	return c.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical TLV keygen confirmation using
// explicit local resource limits.
func (c *KeygenConfirmation) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	var decoded KeygenConfirmation
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.payloadFrameLimits()),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*c = *decoded.Clone()
	return nil
}

func keygenGroupCommitmentsHash(commitments [][]byte) []byte {
	t := transcript.New(keygenConfirmationWireType)
	t.AppendBytesList("group_commitments", commitments)
	return t.Sum()
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
