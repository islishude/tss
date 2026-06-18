package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
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
	Parties         tss.PartySet  `wire:"4,u32list"`
	PublicKey       []byte        `wire:"5,bytes"`
	TranscriptHash  []byte        `wire:"6,bytes"`
	CommitmentsHash []byte        `wire:"7,bytes"`
	ChainCode       []byte        `wire:"8,bytes"`
	PlanHash        []byte        `wire:"9,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for KeygenConfirmation.
func (KeygenConfirmation) WireType() string { return keygenConfirmationWireType }

// WireVersion returns the wire format version for KeygenConfirmation.
func (KeygenConfirmation) WireVersion() uint16 { return keygenConfirmationWireVersion }

// Clone returns a deep copy of the confirmation.
func (c *KeygenConfirmation) Clone() *KeygenConfirmation {
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
	return &KeygenConfirmation{
		SessionID:       k.state.paillierProofSessionID,
		Sender:          k.state.party,
		Threshold:       k.state.threshold,
		Parties:         slices.Clone(k.state.parties),
		PublicKey:       slices.Clone(k.state.publicKey),
		TranscriptHash:  slices.Clone(k.state.keygenTranscriptHash),
		CommitmentsHash: keygenCommitmentsHash(k.state.groupCommitments),
		ChainCode:       slices.Clone(k.state.chainCode),
		PlanHash:        slices.Clone(k.state.planHash),
	}, nil
}

func keygenCommitmentsHash(commitments [][]byte) []byte {
	t := transcript.New(keygenCommitmentsHashLabel)
	t.AppendBytesList("group_commitments", commitments)
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
	return wire.Marshal(c)
}

// UnmarshalKeygenConfirmation decodes a canonical TLV keygen confirmation.
// wire.Unmarshal calls Validate via the Validator interface.
func UnmarshalKeygenConfirmation(in []byte) (*KeygenConfirmation, error) {
	return tss.DecodeBinary[KeygenConfirmation](in)
}

// UnmarshalBinary decodes a canonical TLV keygen confirmation.
func (c *KeygenConfirmation) UnmarshalBinary(in []byte) error {
	var decoded KeygenConfirmation
	if err := wire.Unmarshal(in, &decoded); err != nil {
		return err
	}
	*c = decoded
	return nil
}

// compareKeygenConfirmation checks that a received confirmation matches the local
// reference on every transcript-binding field.
func compareKeygenConfirmation(local, c *KeygenConfirmation) error {
	if c.SessionID != local.SessionID {
		return fmt.Errorf("keygen confirmation session mismatch from party %d", c.Sender)
	}
	if c.Threshold != local.Threshold {
		return fmt.Errorf("keygen confirmation threshold mismatch from party %d: got %d, want %d", c.Sender, c.Threshold, local.Threshold)
	}
	if !slices.Equal(c.Parties, local.Parties) {
		return fmt.Errorf("keygen confirmation party set mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.PublicKey, local.PublicKey) {
		return fmt.Errorf("keygen confirmation public key mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.TranscriptHash, local.TranscriptHash) {
		return fmt.Errorf("keygen confirmation transcript mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.CommitmentsHash, local.CommitmentsHash) {
		return fmt.Errorf("keygen confirmation commitments mismatch from party %d", c.Sender)
	}
	if !bytes.Equal(c.PlanHash, local.PlanHash) {
		return fmt.Errorf("keygen confirmation from party %d: %w", c.Sender, errPlanHashMismatch)
	}
	return nil
}

// verifyFinalizedKeygenConfirmationSet verifies confirmations that were already
// validated and canonicality-checked at receipt time. It does NOT re-unmarshal
// or re-check canonical encoding. Chain code is NOT enforced here because the
// aggregate has not been computed yet; callers handle chain code separately.
func verifyFinalizedKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	n := len(local.state.parties)
	if len(confirmations) != n {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(confirmations), n)
	}
	localConf, err := local.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}
	seen := make(map[tss.PartyID]struct{}, n)
	for i, c := range confirmations {
		expectedSender := local.state.parties[i]
		if c == nil {
			return fmt.Errorf("nil keygen confirmation at index %d for party %d", i, expectedSender)
		}
		if c.Sender != expectedSender {
			return fmt.Errorf("keygen confirmation order mismatch at index %d: got party %d, want %d", i, c.Sender, expectedSender)
		}
		if _, ok := seen[c.Sender]; ok {
			return fmt.Errorf("duplicate keygen confirmation from party %d", c.Sender)
		}
		seen[c.Sender] = struct{}{}
		if err := compareKeygenConfirmation(localConf, c); err != nil {
			return err
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
	return compareKeygenConfirmation(localConf, c)
}

// verifyKeygenConfirmationSetPreservedChainCodeStruct validates confirmations
// with preserved chain code enforcement using pre-parsed structs.
func verifyKeygenConfirmationSetPreservedChainCodeStruct(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if err := verifyFinalizedKeygenConfirmationSet(local, confirmations); err != nil {
		return err
	}
	for _, c := range confirmations {
		if !bytes.Equal(c.ChainCode, local.state.chainCode) {
			return fmt.Errorf("keygen confirmation chain code mismatch from party %d", c.Sender)
		}
	}
	return nil
}

func verifyKeygenConfirmationForPreservedChainCode(local *KeyShare, c *KeygenConfirmation) error {
	if err := verifyKeygenConfirmationForShare(local, c); err != nil {
		return err
	}
	if !bytes.Equal(c.ChainCode, local.state.chainCode) {
		return fmt.Errorf("keygen confirmation chain code mismatch from party %d", c.Sender)
	}
	return nil
}

func applyKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation, limits Limits) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := local.validateWithoutConfirmations(limits); err != nil {
		return fmt.Errorf("invalid local key share: %w", err)
	}
	if len(confirmations) != len(local.state.parties) {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(confirmations), len(local.state.parties))
	}
	for i, confirmation := range confirmations {
		if confirmation == nil {
			return fmt.Errorf("nil keygen confirmation at index %d", i)
		}
		if confirmation.Sender != local.state.parties[i] {
			return fmt.Errorf("keygen confirmation order mismatch at index %d: got party %d, want %d", i, confirmation.Sender, local.state.parties[i])
		}
	}
	if err := verifyFinalizedKeygenConfirmationSet(local, confirmations); err != nil {
		return err
	}
	local.state.keygenConfirmations = tss.CloneSlices(confirmations)
	return nil
}
func keygenConfirmationSetHash(confirmations []*KeygenConfirmation) []byte {
	t := transcript.New(keygenConfirmationWireType)
	for _, c := range confirmations {
		encoded, err := c.MarshalBinary()
		if err != nil {
			return nil
		}
		t.AppendBytes("confirmation", encoded)
	}
	return t.Sum()
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
	if err := requirePlanHash("keygen confirmation", confirmation.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	pd, entryErr := s.partyEntry(env.From)
	if entryErr != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, entryErr)
	}
	if pd.confirmation != nil {
		existing, err := pd.confirmation.MarshalBinary()
		if err == nil && bytes.Equal(existing, canonical) {
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
		if err := verifyKeygenConfirmationForShare(s.pending, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	// Verify the revealed chain code against the round 1 hash commitment.
	if !verifyCGGMPChainCodeCommit(s.cfg.SessionID, env.From, confirmation.ChainCode, pd.chainCodeCommit) {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("keygen confirmation chain code does not match round 1 commit from party %d", env.From))
	}

	// ---- 4. MUTATE STATE ----
	// Store the revealed chain code for XOR aggregation.
	pd.chainCode = bytes.Clone(confirmation.ChainCode)
	pd.confirmation = confirmation

	// ---- 5. EMIT ----
	if s.pending != nil && allConfirmationsReceived(s.partyData, s.cfg.Parties) {
		return nil, s.finalizeConfirmedKeyShare()
	}
	return nil, nil
}

// allConfirmationsReceived returns true when every party has submitted a confirmation.
func allConfirmationsReceived(pd map[tss.PartyID]*keygenPartyData, parties tss.PartySet) bool {
	for _, id := range parties {
		d := pd[id]
		if d == nil || d.confirmation == nil {
			return false
		}
	}
	return true
}

// finalizeConfirmedKeyShare verifies the full confirmation set and produces the
// final key share with the aggregate chain code.
func (s *KeygenSession) finalizeConfirmedKeyShare() error {
	if s.pending == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("missing pending key share"))
	}
	// Collect parsed confirmations in party order (no re-unmarshal needed).
	confirmations := make([]*KeygenConfirmation, len(s.cfg.Parties))
	for i, id := range s.cfg.Parties {
		c := s.partyData[id].confirmation
		if c == nil {
			s.abort()
			return tss.NewProtocolError(
				tss.ErrCodeVerification,
				keygenConfirmationRound,
				id,
				fmt.Errorf("missing keygen confirmation from party %d", id),
			)
		}
		confirmations[i] = c
	}
	if err := verifyFinalizedKeygenConfirmationSet(s.pending, confirmations); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	// Aggregate chain codes from all revealed confirmations.
	chainCodeMap := make(map[tss.PartyID][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		chainCodeMap[id] = s.partyData[id].chainCode
	}
	chainCode, err := bip32util.AggregateChainCode(s.cfg.Parties, chainCodeMap)
	if err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	finalShare := cloneKeyShareValue(s.pending)
	finalShare.state.chainCode = chainCode
	// Recomputation: now that we have the real chain codes, produce the final
	// transcript hash that binds them.
	finalShare.state.keygenTranscriptHash = s.keygenTranscriptHash(finalShare.state.groupCommitments)
	// Store parsed confirmation structs directly.
	finalShare.state.keygenConfirmations = tss.CloneSlices(confirmations)
	if err := finalShare.ValidateWithLimits(s.limits); err != nil {
		finalShare.Destroy()
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	s.pending.Destroy()
	s.pending = nil
	s.keyShare = finalShare
	s.completed = true
	s.state = keygenConfirmed
	pubKeyHash := sha256.Sum256(finalShare.state.publicKey)
	confirmationSetHash := keygenConfirmationSetHash(finalShare.state.keygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", pubKeyHash[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}
