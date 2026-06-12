package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
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
	Parties         []tss.PartyID `wire:"4,u32list"`
	PublicKey       []byte        `wire:"5,bytes"`
	TranscriptHash  []byte        `wire:"6,bytes"`
	CommitmentsHash []byte        `wire:"7,bytes"`
	ChainCode       []byte        `wire:"8,bytes"`
}

// WireType returns the canonical wire type identifier for KeygenConfirmation.
func (KeygenConfirmation) WireType() string { return keygenConfirmationWireType }

// WireVersion returns the wire format version for KeygenConfirmation.
func (KeygenConfirmation) WireVersion() uint16 { return keygenConfirmationWireVersion }

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
		ChainCode:       slices.Clone(k.ChainCode),
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
	if len(c.ChainCode) != 0 && len(c.ChainCode) != 32 {
		return errors.New("keygen confirmation: chain code must be empty or 32 bytes")
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
	return wire.Marshal(c)
}

// UnmarshalKeygenConfirmation decodes a canonical TLV keygen confirmation.
// wire.Unmarshal calls Validate via the Validator interface.
func UnmarshalKeygenConfirmation(in []byte) (*KeygenConfirmation, error) {
	var c KeygenConfirmation
	if err := wire.Unmarshal(in, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func verifyKeygenConfirmationSet(local *KeyShare, encoded [][]byte) error {
	return verifyKeygenConfirmationSetInternal(local, encoded, true)
}

// verifyKeygenConfirmationSetWithoutChainCode validates the confirmation set
// without enforcing the aggregate chain code. It is used before the aggregate
// is computed (e.g., during finalizeConfirmedKeyShare).
func verifyKeygenConfirmationSetWithoutChainCode(local *KeyShare, encoded [][]byte) error {
	return verifyKeygenConfirmationSetInternal(local, encoded, false)
}

func verifyKeygenConfirmationSetInternal(local *KeyShare, encoded [][]byte, enforceChainCode bool) error {
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
	chainCodes := make(map[tss.PartyID][]byte, n)
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
		chainCodes[c.Sender] = slices.Clone(c.ChainCode)
	}

	for _, id := range local.Parties {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("missing keygen confirmation from party %d", id)
		}
	}

	if enforceChainCode {
		if len(local.ChainCode) == 0 {
			for _, id := range local.Parties {
				if len(chainCodes[id]) != 0 {
					return fmt.Errorf("keygen confirmation from party %d has unexpected chain code", id)
				}
			}
		} else {
			aggregate, err := bip32util.AggregateChainCode(local.Parties, chainCodes)
			if err != nil {
				return fmt.Errorf("keygen confirmation chain code set: %w", err)
			}
			if !bytes.Equal(aggregate, local.ChainCode) {
				return errors.New("keygen confirmation aggregate chain code mismatch")
			}
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

// handleKeygenConfirmation validates and applies a keygen confirmation message.
//
// Follows the handler template (see doc.go).
func (s *KeygenSession) handleKeygenConfirmation(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	confirmation, err := UnmarshalKeygenConfirmation(env.Payload)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}

	// ---- 2. POLICY VALIDATE ----
	if confirmation.Sender != env.From {
		return nil, tss.NewProtocolError(
			tss.ErrCodeInvalidMessage,
			env.Round,
			env.From,
			fmt.Errorf("keygen confirmation sender mismatch: env from %d, payload sender %d", env.From, confirmation.Sender),
		)
	}
	canonical, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical keygen confirmation"))
	}
	if existing, ok := s.confirmations[env.From]; ok {
		if bytes.Equal(existing, canonical) {
			return nil, nil
		}
		return nil, tss.NewProtocolError(
			tss.ErrCodeVerification,
			env.Round,
			env.From,
			fmt.Errorf("conflicting keygen confirmation from party %d", env.From),
		)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if s.pending != nil {
		if err := verifyKeygenConfirmationForShare(s.pending.share, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	// Verify the revealed chain code against the round 1 hash commitment.
	if !verifyCGGMPChainCodeCommit(s.cfg.SessionID, env.From, confirmation.ChainCode, s.chainCodeComms[env.From]) {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("keygen confirmation chain code does not match round 1 commit from party %d", env.From))
	}

	// ---- 4. MUTATE STATE ----
	// Store the revealed chain code for XOR aggregation.
	s.chainCodes[env.From] = append([]byte(nil), confirmation.ChainCode...)
	s.confirmations[env.From] = append([]byte(nil), canonical...)

	// ---- 5. EMIT ----
	if s.pending != nil && len(s.confirmations) == len(s.cfg.Parties) {
		return nil, s.finalizeConfirmedKeyShare()
	}
	return nil, nil
}

// finalizeConfirmedKeyShare verifies the full confirmation set and produces the
// final key share with the aggregate chain code.
func (s *KeygenSession) finalizeConfirmedKeyShare() error {
	if s.pending == nil || s.pending.share == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("missing pending key share"))
	}
	encoded := make([][]byte, len(s.cfg.Parties))
	for i, id := range s.cfg.Parties {
		confirmation, ok := s.confirmations[id]
		if !ok {
			s.abort()
			return tss.NewProtocolError(
				tss.ErrCodeVerification,
				keygenConfirmationRound,
				id,
				fmt.Errorf("missing keygen confirmation from party %d", id),
			)
		}
		encoded[i] = append([]byte(nil), confirmation...)
	}
	if err := verifyKeygenConfirmationSetWithoutChainCode(s.pending.share, encoded); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	// Aggregate chain codes from all revealed confirmations.
	var chainCode []byte
	if s.enableHD {
		cc, err := bip32util.AggregateChainCode(s.cfg.Parties, s.chainCodes)
		if err != nil {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
		}
		chainCode = cc
	}
	finalShare := s.pending.share.Clone()
	finalShare.ChainCode = chainCode
	// Recomputation: now that we have the real chain codes, produce the final
	// transcript hash that binds them.
	finalShare.KeygenTranscriptHash = s.keygenTranscriptHash(finalShare.GroupCommitments)
	finalShare.KeygenConfirmations = cloneKeyShareByteSlices(encoded)
	if err := finalShare.Validate(); err != nil {
		finalShare.Destroy()
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	s.pending.share.Destroy()
	s.pending = nil
	s.keyShare = finalShare
	s.completed = true
	s.state = keygenConfirmed
	pubKeyHash := sha256.Sum256(finalShare.PublicKey)
	confirmationSetHash := keygenConfirmationSetHash(finalShare.KeygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", pubKeyHash[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}
