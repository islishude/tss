package ed25519

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

const keygenConfirmationWireType = "frost.ed25519.keygen-confirmation"

// KeygenConfirmation is a post-keygen consistency artifact. Each party
// broadcasts one after local DKG material verifies. The transcript hash binds
// the session ID, threshold, sorted party set, aggregate chain code, every
// dealer commitment set, group commitments, group public key, and verification
// shares. ChainCode is revealed here (round 2) after its hash commitment was
// broadcast in round 1, preventing last-sender bias on the XOR-aggregated group
// chain code. If any confirmation disagrees, the transport may have equivocated
// and the resulting key shares must not be used.
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

// NewConfirmation constructs a confirmation message from the local key
// share.
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
		SessionID:       k.state.keygenSessionID,
		Sender:          k.state.party,
		Threshold:       k.state.threshold,
		Parties:         slices.Clone(k.state.parties),
		PublicKey:       k.state.publicKey.Clone(),
		TranscriptHash:  slices.Clone(k.state.keygenTranscriptHash),
		CommitmentsHash: keygenGroupCommitmentsHash(k.state.groupCommitments.BytesList()),
		ChainCode:       slices.Clone(k.state.chainCode),
		PlanHash:        slices.Clone(k.state.planHash),
	}, nil
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
// wire.Marshal calls Validate via the Validator interface.
func (c KeygenConfirmation) MarshalBinary() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(c)
}

// UnmarshalBinary decodes a canonical TLV keygen confirmation.
func (c *KeygenConfirmation) UnmarshalBinary(in []byte) error {
	var decoded KeygenConfirmation
	if err := wire.Unmarshal(in, &decoded); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*c = *decoded.Clone()
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
	if !c.PublicKey.Equal(local.PublicKey) {
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
// or re-check canonical encoding. When enforceChainCode is true, the aggregate
// chain code is verified against local.state.chainCode.
func verifyFinalizedKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation, enforceChainCode bool) error {
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
	chainCodes := make(map[tss.PartyID][]byte, n)
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
		if enforceChainCode {
			chainCodes[c.Sender] = slices.Clone(c.ChainCode)
		}
	}
	if enforceChainCode {
		aggregate, err := bip32util.AggregateChainCode(local.state.parties, chainCodes)
		if err != nil {
			return fmt.Errorf("keygen confirmation chain code set: %w", err)
		}
		if !bytes.Equal(aggregate, local.state.chainCode) {
			return errors.New("keygen confirmation aggregate chain code mismatch")
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

func applyKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := local.validateWithoutConfirmations(); err != nil {
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
		if !slices.Contains(local.state.parties, confirmation.Sender) {
			return fmt.Errorf("keygen confirmation from unknown party %d", confirmation.Sender)
		}
	}
	if err := verifyFinalizedKeygenConfirmationSet(local, confirmations, false); err != nil {
		return err
	}
	for _, confirmation := range confirmations {
		data := local.state.partyData[confirmation.Sender]
		data.keygenConfirmation = confirmation.Clone()
		local.state.partyData[confirmation.Sender] = data
	}
	return nil
}

func keygenGroupCommitmentsHash(commitments [][]byte) []byte {
	t := transcript.New(keygenConfirmationWireType)
	t.AppendBytesList("group_commitments", commitments)
	return t.Sum()
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

func (s *KeygenSession) finalizeConfirmedKeyShare() error {
	prepared, ok, err := s.maybePrepareFinalKeyShare()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer prepared.destroy()
	s.commitFinalKeyShare(prepared)
	return nil
}

type preparedFinalKeyShare struct {
	share               *KeyShare
	confirmationSetHash []byte
	committed           bool
}

func (p *preparedFinalKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
		p.share = nil
	}
	clear(p.confirmationSetHash)
}

func (s *KeygenSession) maybePrepareFinalKeyShare() (*preparedFinalKeyShare, bool, error) {
	if s.pending == nil {
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("missing pending key share"))
	}
	if !allConfirmationsReceived(s.partyData, s.cfg.Parties) {
		return nil, false, nil
	}
	// Collect parsed confirmations in party order (no re-unmarshal needed).
	confirmations := make([]*KeygenConfirmation, len(s.cfg.Parties))
	for i, id := range s.cfg.Parties {
		c := s.partyData[id].confirmation
		if c == nil {
			return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing keygen confirmation from party %d", id))
		}
		confirmations[i] = c
	}
	if err := verifyFinalizedKeygenConfirmationSet(s.pending, confirmations, false); err != nil {
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	// Aggregate chain codes from all revealed confirmations.
	chainCodeMap := make(map[tss.PartyID][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		chainCodeMap[id] = s.partyData[id].chainCode
	}
	chainCode, err := bip32util.AggregateChainCode(s.cfg.Parties, chainCodeMap)
	if err != nil {
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	finalShare := cloneKeyShareValue(s.pending)
	finalShare.state.chainCode = chainCode
	// Recompute transcript hash now that confirmations carry the final chain
	// codes (matching the CGGMP21 pattern at keygen_confirm.go:437-439).
	chainCodeCommitMap := make(map[tss.PartyID][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		chainCodeCommitMap[id] = s.partyData[id].chainCodeCommit
	}
	chainCodeCommitAggregate, err := bip32util.AggregateChainCode(s.cfg.Parties, chainCodeCommitMap)
	if err != nil {
		finalShare.Destroy()
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	dealerCommits := make(map[tss.PartyID][][]byte, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		dealerCommits[id] = s.partyData[id].commitments.BytesList()
	}
	verificationShares, err := finalShare.orderedVerificationShares()
	if err != nil {
		finalShare.Destroy()
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	finalShare.state.keygenTranscriptHash = frostKeygenTranscriptHash(
		s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties,
		chainCodeCommitAggregate, s.planHash, dealerCommits,
		finalShare.state.groupCommitments.BytesList(), verificationShares,
	)
	// Store parsed confirmation structs directly.
	if err := applyKeygenConfirmationSet(finalShare, confirmations); err != nil {
		finalShare.Destroy()
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	if err := finalShare.ValidateConsistency(); err != nil {
		finalShare.Destroy()
		return nil, false, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	return &preparedFinalKeyShare{
		share:               finalShare,
		confirmationSetHash: keygenConfirmationSetHash(confirmations),
	}, true, nil
}

func (s *KeygenSession) commitFinalKeyShare(p *preparedFinalKeyShare) {
	if p == nil {
		return
	}
	s.pending.Destroy()
	s.pending = nil
	s.keyShare = p.share
	s.completed = true
	s.clearIntermediateSecrets()
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", p.confirmationSetHash[:8]),
	)
	p.committed = true
}
