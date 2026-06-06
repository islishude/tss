package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const keygenConfirmationWireVersion = 1

const keygenConfirmationWireType = "cggmp21.secp256k1.keygen-confirmation"

const (
	keygenConfirmationFieldSessionID uint16 = iota + 1
	keygenConfirmationFieldSender
	keygenConfirmationFieldThreshold
	keygenConfirmationFieldParties
	keygenConfirmationFieldPublicKey
	keygenConfirmationFieldTranscriptHash
	keygenConfirmationFieldCommitmentsHash
)

// KeygenConfirmation is a post-keygen consistency artifact. Each party produces
// one after keygen completes and exchanges it with all other parties. If any
// party's confirmation disagrees on the global transcript (public key, party set,
// transcript hash, or commitments hash), the transport may have equivocated and
// the resulting key shares must not be used.
type KeygenConfirmation struct {
	SessionID       tss.SessionID
	Sender          tss.PartyID
	Threshold       int
	Parties         []tss.PartyID
	PublicKey       []byte
	TranscriptHash  []byte
	CommitmentsHash []byte
}

// KeygenConfirmation constructs a confirmation message from the local key share.
func (k *KeyShare) KeygenConfirmation() (*KeygenConfirmation, error) {
	if err := k.validateWithoutConfirmations(); err != nil {
		return nil, fmt.Errorf("cannot build keygen confirmation: %w", err)
	}
	return k.keygenConfirmationReferenceUnchecked()
}

func (k *KeyShare) keygenConfirmationReferenceUnchecked() (*KeygenConfirmation, error) {
	if k == nil {
		return nil, errors.New("nil key share")
	}
	h := sha256.New()
	wire.WriteHashPart(h, wire.EncodeBytesList(k.GroupCommitments))
	return &KeygenConfirmation{
		SessionID:       k.PaillierProofSessionID,
		Sender:          k.Party,
		Threshold:       k.Threshold,
		Parties:         slices.Clone(k.Parties),
		PublicKey:       slices.Clone(k.PublicKey),
		TranscriptHash:  slices.Clone(k.KeygenTranscriptHash),
		CommitmentsHash: h.Sum(nil),
	}, nil
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
	if len(c.PublicKey) == 0 {
		return errors.New("keygen confirmation: empty public key")
	}
	if len(c.TranscriptHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid transcript hash length")
	}
	if len(c.CommitmentsHash) != sha256.Size {
		return errors.New("keygen confirmation: invalid commitments hash length")
	}
	if err := wire.ValidateStrictSortedIDs(c.Parties); err != nil {
		return fmt.Errorf("keygen confirmation: %w", err)
	}
	if !slices.Contains(c.Parties, c.Sender) {
		return errors.New("keygen confirmation: sender not in party set")
	}
	return nil
}

// MarshalBinary encodes the confirmation in canonical TLV format.
func (c KeygenConfirmation) MarshalBinary() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(keygenConfirmationWireVersion, keygenConfirmationWireType, []wire.Field{
		{Tag: keygenConfirmationFieldSessionID, Value: c.SessionID[:]},
		{Tag: keygenConfirmationFieldSender, Value: wire.Uint32(uint32(c.Sender))},
		{Tag: keygenConfirmationFieldThreshold, Value: wire.Uint32(uint32(c.Threshold))},
		{Tag: keygenConfirmationFieldParties, Value: wire.EncodeUint32List(c.Parties)},
		{Tag: keygenConfirmationFieldPublicKey, Value: wire.NonNilBytes(c.PublicKey)},
		{Tag: keygenConfirmationFieldTranscriptHash, Value: wire.NonNilBytes(c.TranscriptHash)},
		{Tag: keygenConfirmationFieldCommitmentsHash, Value: wire.NonNilBytes(c.CommitmentsHash)},
	})
}

// UnmarshalKeygenConfirmation decodes a canonical TLV keygen confirmation.
func UnmarshalKeygenConfirmation(in []byte) (*KeygenConfirmation, error) {
	version, fields, err := wire.Unmarshal(in, keygenConfirmationWireType)
	if err != nil {
		return nil, err
	}
	if version != keygenConfirmationWireVersion {
		return nil, fmt.Errorf("unexpected keygen confirmation version %d", version)
	}
	if err := wire.RequireExactTags(fields,
		keygenConfirmationFieldSessionID,
		keygenConfirmationFieldSender,
		keygenConfirmationFieldThreshold,
		keygenConfirmationFieldParties,
		keygenConfirmationFieldPublicKey,
		keygenConfirmationFieldTranscriptHash,
		keygenConfirmationFieldCommitmentsHash,
	); err != nil {
		return nil, err
	}

	sessionID, err := tss.SessionIDFromBytes(wire.MustField(fields, keygenConfirmationFieldSessionID))
	if err != nil {
		return nil, fmt.Errorf("keygen confirmation session id: %w", err)
	}
	sender, err := wire.Uint32Field(fields, keygenConfirmationFieldSender)
	if err != nil {
		return nil, fmt.Errorf("keygen confirmation sender: %w", err)
	}
	threshold, err := wire.Uint32Field(fields, keygenConfirmationFieldThreshold)
	if err != nil {
		return nil, fmt.Errorf("keygen confirmation threshold: %w", err)
	}
	parties, err := wire.Uint32ListField[tss.PartyID](fields, keygenConfirmationFieldParties)
	if err != nil {
		return nil, fmt.Errorf("keygen confirmation parties: %w", err)
	}

	c := &KeygenConfirmation{
		SessionID:       sessionID,
		Sender:          tss.PartyID(sender),
		Threshold:       int(threshold),
		Parties:         slices.Clone(parties),
		PublicKey:       slices.Clone(wire.MustField(fields, keygenConfirmationFieldPublicKey)),
		TranscriptHash:  slices.Clone(wire.MustField(fields, keygenConfirmationFieldTranscriptHash)),
		CommitmentsHash: slices.Clone(wire.MustField(fields, keygenConfirmationFieldCommitmentsHash)),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func verifyKeygenConfirmationSet(local *KeyShare, encoded [][]byte) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	n := len(local.Parties)
	if len(encoded) == 0 {
		return errors.New("missing keygen confirmations")
	}
	if len(encoded) != n {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(encoded), n)
	}

	localConf, err := local.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}

	seen := make(map[tss.PartyID]struct{}, n)
	for i, raw := range encoded {
		expectedSender := local.Parties[i]
		if len(raw) == 0 {
			return fmt.Errorf("empty keygen confirmation at index %d for party %d", i, expectedSender)
		}
		c, err := UnmarshalKeygenConfirmation(raw)
		if err != nil {
			return fmt.Errorf("invalid keygen confirmation at index %d for party %d: %w", i, expectedSender, err)
		}
		canonical, err := c.MarshalBinary()
		if err != nil {
			return fmt.Errorf("keygen confirmation from party %d: %w", c.Sender, err)
		}
		if !bytes.Equal(canonical, raw) {
			return fmt.Errorf("non-canonical keygen confirmation from party %d", c.Sender)
		}
		if !slices.Contains(local.Parties, c.Sender) {
			return fmt.Errorf("keygen confirmation from unknown party %d", c.Sender)
		}
		if _, ok := seen[c.Sender]; ok {
			return fmt.Errorf("duplicate keygen confirmation from party %d", c.Sender)
		}
		seen[c.Sender] = struct{}{}
		if c.Sender != expectedSender {
			return fmt.Errorf("keygen confirmation order mismatch at index %d: got party %d, want %d", i, c.Sender, expectedSender)
		}
		if c.SessionID != localConf.SessionID {
			return fmt.Errorf("keygen confirmation session mismatch from party %d", c.Sender)
		}
		if c.Threshold != localConf.Threshold {
			return fmt.Errorf("keygen confirmation threshold mismatch from party %d: got %d, want %d", c.Sender, c.Threshold, localConf.Threshold)
		}
		if !slices.Equal(c.Parties, localConf.Parties) {
			return fmt.Errorf("keygen confirmation party set mismatch from party %d", c.Sender)
		}
		if !bytes.Equal(c.PublicKey, localConf.PublicKey) {
			return fmt.Errorf("keygen confirmation public key mismatch from party %d", c.Sender)
		}
		if !bytes.Equal(c.TranscriptHash, localConf.TranscriptHash) {
			return fmt.Errorf("keygen confirmation transcript mismatch from party %d", c.Sender)
		}
		if !bytes.Equal(c.CommitmentsHash, localConf.CommitmentsHash) {
			return fmt.Errorf("keygen confirmation commitments mismatch from party %d", c.Sender)
		}
	}

	for _, id := range local.Parties {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("missing keygen confirmation from party %d", id)
		}
	}

	return nil
}

func verifyKeygenConfirmationForShare(local *KeyShare, c *KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if c == nil {
		return errors.New("nil keygen confirmation")
	}
	localConf, err := local.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}
	if c.SessionID != localConf.SessionID {
		return fmt.Errorf("keygen confirmation session mismatch from party %d", c.Sender)
	}
	if c.Threshold != localConf.Threshold {
		return fmt.Errorf("keygen confirmation threshold mismatch from party %d: got %d, want %d", c.Sender, c.Threshold, localConf.Threshold)
	}
	if !slices.Equal(c.Parties, localConf.Parties) {
		return fmt.Errorf("keygen confirmation party set mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.PublicKey, localConf.PublicKey) {
		return fmt.Errorf("keygen confirmation public key mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.TranscriptHash, localConf.TranscriptHash) {
		return fmt.Errorf("keygen confirmation transcript mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.CommitmentsHash, localConf.CommitmentsHash) {
		return fmt.Errorf("keygen confirmation commitments mismatch from party %d", c.Sender)
	}
	return nil
}

func applyKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := local.validateWithoutConfirmations(); err != nil {
		return fmt.Errorf("invalid local key share: %w", err)
	}
	if len(confirmations) != len(local.Parties) {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(confirmations), len(local.Parties))
	}
	bySender := make(map[tss.PartyID][]byte, len(confirmations))
	for _, confirmation := range confirmations {
		if confirmation == nil {
			return errors.New("nil keygen confirmation in set")
		}
		if !slices.Contains(local.Parties, confirmation.Sender) {
			return fmt.Errorf("keygen confirmation from unknown party %d", confirmation.Sender)
		}
		if _, ok := bySender[confirmation.Sender]; ok {
			return fmt.Errorf("duplicate keygen confirmation from party %d", confirmation.Sender)
		}
		encoded, err := confirmation.MarshalBinary()
		if err != nil {
			return fmt.Errorf("keygen confirmation from party %d: %w", confirmation.Sender, err)
		}
		bySender[confirmation.Sender] = encoded
	}
	encoded := make([][]byte, len(local.Parties))
	for i, id := range local.Parties {
		item, ok := bySender[id]
		if !ok {
			return fmt.Errorf("missing keygen confirmation from party %d", id)
		}
		encoded[i] = item
	}
	if err := verifyKeygenConfirmationSet(local, encoded); err != nil {
		return err
	}
	local.KeygenConfirmations = cloneKeyShareByteSlices(encoded)
	return nil
}

func keygenConfirmationSetHash(encoded [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(keygenConfirmationWireType))
	wire.WriteHashPart(h, wire.EncodeBytesList(encoded))
	return h.Sum(nil)
}
