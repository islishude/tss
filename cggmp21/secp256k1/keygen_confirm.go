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
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("cannot build keygen confirmation: %w", err)
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

// VerifyKeygenConfirmations checks that all parties have confirmed the same
// keygen transcript. On success, local.KeygenConfirmed is set to true.
// Callers must exchange confirmations through authenticated transport before
// calling this function. A key share must not be used for presign or signing
// until this function succeeds.
func VerifyKeygenConfirmations(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := local.Validate(); err != nil {
		return fmt.Errorf("invalid local key share: %w", err)
	}

	n := len(local.Parties)
	if len(confirmations) != n {
		return fmt.Errorf("got %d confirmations, want %d", len(confirmations), n)
	}

	// Build reference confirmation from the local share.
	localConf, err := local.KeygenConfirmation()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}

	seen := make(map[tss.PartyID]bool)
	for _, c := range confirmations {
		if c == nil {
			return errors.New("nil confirmation in set")
		}
		if err := c.Validate(); err != nil {
			return fmt.Errorf("confirmation from party %d: %w", c.Sender, err)
		}

		// No duplicate senders.
		if seen[c.Sender] {
			return fmt.Errorf("duplicate confirmation from party %d", c.Sender)
		}
		seen[c.Sender] = true

		// Unknown sender.
		if !slices.Contains(local.Parties, c.Sender) {
			return fmt.Errorf("confirmation from unknown party %d", c.Sender)
		}

		// Session ID must match.
		if c.SessionID != localConf.SessionID {
			return fmt.Errorf("party %d session id mismatch", c.Sender)
		}
		// Threshold must match.
		if c.Threshold != localConf.Threshold {
			return fmt.Errorf("party %d threshold mismatch: got %d, want %d", c.Sender, c.Threshold, localConf.Threshold)
		}
		// Party set must match (order-sensitive).
		if !slices.Equal(c.Parties, localConf.Parties) {
			return fmt.Errorf("party %d party set mismatch", c.Sender)
		}
		// Public key must match.
		if !bytes.Equal(c.PublicKey, localConf.PublicKey) {
			return fmt.Errorf("party %d public key mismatch", c.Sender)
		}
		// Transcript hash must match.
		if !bytes.Equal(c.TranscriptHash, localConf.TranscriptHash) {
			return fmt.Errorf("party %d transcript hash mismatch", c.Sender)
		}
		// Commitments hash must match.
		if !bytes.Equal(c.CommitmentsHash, localConf.CommitmentsHash) {
			return fmt.Errorf("party %d commitments hash mismatch", c.Sender)
		}
	}

	// Every expected party must have sent a confirmation.
	for _, id := range local.Parties {
		if !seen[id] {
			return fmt.Errorf("missing confirmation from party %d", id)
		}
	}

	local.KeygenConfirmed = true
	return nil
}
