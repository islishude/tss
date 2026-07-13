package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/tssrun"
)

const (
	childDerivationPlanDigestLabel = "cggmp21-secp256k1-child-derivation-plan-v1"
	childDerivationSIDLabel        = "cggmp21-secp256k1-child-lineage-sid-v1"
)

// ChildDerivationPlanOption configures a canonical, non-hardened BIP32 child
// epoch plan. Parent is used only to construct and validate shared public
// derivation metadata; StartChildDerivation later reloads the authoritative
// secret parent generation from LifecycleStore.
type ChildDerivationPlanOption struct {
	Parent              *KeyShare
	ParentBinding       tssrun.GenerationBinding
	SessionID           tss.SessionID
	Path                tss.DerivationPath
	InvalidChildMode    tss.InvalidChildMode
	TargetKeyID         string
	TargetKeyGeneration tssrun.KeyGeneration
	PaillierBits        int
	Limits              *Limits
	SecurityParams      *SecurityParams
}

// ChildDerivationPlan is the opaque shared intent for creating one sign-ready
// non-hardened BIP32 child key as a distinct durable key lineage.
type ChildDerivationPlan struct {
	state  *childDerivationPlanState
	limits Limits
}

type childDerivationPlanState struct {
	ParentKeyID         string               `wire:"1,string"`
	ParentKeyGeneration string               `wire:"2,string"`
	ParentEpochID       []byte               `wire:"3,bytes,len=32"`
	ParentSID           tss.SessionID        `wire:"4,bytes,len=32"`
	SessionID           tss.SessionID        `wire:"5,bytes,len=32"`
	TargetKeyID         string               `wire:"6,string"`
	TargetKeyGeneration string               `wire:"7,string"`
	RequestedPath       tss.DerivationPath   `wire:"8,u32list"`
	ResolvedPath        tss.DerivationPath   `wire:"9,u32list"`
	InvalidChildMode    tss.InvalidChildMode `wire:"10,u8"`
	ParentPublicKey     []byte               `wire:"11,bytes,max_bytes=point"`
	ParentChainCode     []byte               `wire:"12,bytes,len=32"`
	ChildPublicKey      []byte               `wire:"13,bytes,max_bytes=point"`
	ChildChainCode      []byte               `wire:"14,bytes,len=32"`
	Tweak               []byte               `wire:"15,bytes,len=32"`
	Depth               uint8                `wire:"16,u8"`
	ParentFingerprint   []byte               `wire:"17,bytes,len=4"`
	ChildNumber         uint32               `wire:"18,u32"`
	Parties             tss.PartySet         `wire:"19,u32list,max_items=parties"`
	Threshold           int                  `wire:"20,u32"`
	PaillierBits        int                  `wire:"21,u32"`
	SecurityParams      SecurityParams       `wire:"22,record"`
	ChildSID            tss.SessionID        `wire:"23,bytes,len=32"`
}

// ChildDerivationPlanSnapshot is a caller-owned public plan snapshot.
type ChildDerivationPlanSnapshot struct {
	ParentBinding       tssrun.GenerationBinding
	ParentSID           tss.SessionID
	SessionID           tss.SessionID
	TargetKeyID         string
	TargetKeyGeneration tssrun.KeyGeneration
	Derivation          *tss.DerivationResult
	Parties             tss.PartySet
	Threshold           int
	PaillierBits        int
	SecurityParams      SecurityParams
	ChildSID            tss.SessionID
}

// Clone returns an independent copy of the snapshot.
func (s ChildDerivationPlanSnapshot) Clone() ChildDerivationPlanSnapshot {
	return ChildDerivationPlanSnapshot{
		ParentBinding:       s.ParentBinding,
		ParentSID:           s.ParentSID,
		SessionID:           s.SessionID,
		TargetKeyID:         s.TargetKeyID,
		TargetKeyGeneration: s.TargetKeyGeneration,
		Derivation:          s.Derivation.Clone(),
		Parties:             s.Parties.Clone(),
		Threshold:           s.Threshold,
		PaillierBits:        s.PaillierBits,
		SecurityParams:      s.SecurityParams,
		ChildSID:            s.ChildSID,
	}
}

// NewChildDerivationPlan constructs a canonical non-hardened child epoch plan.
func NewChildDerivationPlan(option ChildDerivationPlanOption) (*ChildDerivationPlan, error) {
	parent := option.Parent
	limits := limitsOrDefault(option.Limits)
	if parent == nil || parent.state == nil {
		return nil, invalidPlanConfig(0, errors.New("nil child-derivation parent key share"))
	}
	party := parent.state.Party
	if err := option.ParentBinding.Validate(); err != nil {
		return nil, invalidPlanConfig(party, fmt.Errorf("invalid parent generation binding: %w", err))
	}
	if !option.SessionID.Valid() {
		return nil, invalidPlanConfig(party, tss.ErrInvalidSessionID)
	}
	if len(option.Path) == 0 {
		return nil, invalidPlanConfig(party, errors.New("child derivation path must be non-empty"))
	}
	if err := option.Path.ValidateNonHardened(); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	if !option.InvalidChildMode.Valid() {
		return nil, invalidPlanConfig(party, fmt.Errorf("%w: %d", tss.ErrInvalidChildMode, option.InvalidChildMode))
	}
	if err := parent.requireMPCMaterial(limits); err != nil {
		return nil, invalidPlanConfig(party, fmt.Errorf("invalid child-derivation parent key: %w", err))
	}
	if parent.state.Epoch == nil || !bytes.Equal(parent.state.Epoch.EpochID, option.ParentBinding.EpochID[:]) {
		return nil, invalidPlanConfig(party, errors.New("parent binding epoch does not match parent key share"))
	}
	if option.TargetKeyID == option.ParentBinding.KeyID {
		return nil, invalidPlanConfig(party, errors.New("child key id must differ from parent key id"))
	}
	if err := validateChildTargetDescriptor(option.TargetKeyID, option.TargetKeyGeneration, option.ParentBinding.EpochID); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	securityParams := securityParamsForArtifact(parent.state.SecurityParams, option.SecurityParams)
	if option.SecurityParams != nil && parent.state.SecurityParams != *option.SecurityParams {
		return nil, invalidPlanConfig(party, errors.New("security params mismatch with parent key share"))
	}
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	paillierBits := option.PaillierBits
	if paillierBits == 0 {
		paillierBits = int(securityParams.MinPaillierBits)
	}
	if paillierBits < int(securityParams.MinPaillierBits) ||
		(limits.Paillier.MaxModulusBits > 0 && paillierBits > limits.Paillier.MaxModulusBits) {
		return nil, invalidPlanConfig(party, errors.New("child derivation Paillier key size is outside allowed bounds"))
	}
	derivation, err := DeriveNonHardenedBIP32(
		parent.state.PublicKey,
		parent.state.ChainCode,
		option.Path.Clone(),
		tss.WithInvalidChildMode(option.InvalidChildMode),
	)
	if err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	defer derivation.Destroy()
	if err := validateChildDerivationResult(derivation, option.Path, option.InvalidChildMode); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	state := &childDerivationPlanState{
		ParentKeyID:         option.ParentBinding.KeyID,
		ParentKeyGeneration: string(option.ParentBinding.KeyGeneration),
		ParentEpochID:       option.ParentBinding.EpochID.Bytes(),
		ParentSID:           parent.state.Epoch.SID,
		SessionID:           option.SessionID,
		TargetKeyID:         option.TargetKeyID,
		TargetKeyGeneration: string(option.TargetKeyGeneration),
		RequestedPath:       derivation.RequestedPath.Clone(),
		ResolvedPath:        derivation.ResolvedPath.Clone(),
		InvalidChildMode:    option.InvalidChildMode,
		ParentPublicKey:     bytes.Clone(parent.state.PublicKey),
		ParentChainCode:     bytes.Clone(parent.state.ChainCode),
		ChildPublicKey:      bytes.Clone(derivation.ChildPublicKey),
		ChildChainCode:      bytes.Clone(derivation.ChildChainCode),
		Tweak:               bytes.Clone(derivation.AdditiveShift),
		Depth:               derivation.Depth,
		ParentFingerprint:   bytes.Clone(derivation.ParentFingerprint[:]),
		ChildNumber:         derivation.ChildNumber,
		Parties:             parent.state.Parties.Clone(),
		Threshold:           parent.state.Threshold,
		PaillierBits:        paillierBits,
		SecurityParams:      securityParams,
	}
	state.ChildSID, err = deriveChildLineageSID(state)
	if err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	plan := &ChildDerivationPlan{state: state, limits: limits}
	if err := plan.ValidateWithLimits(limits); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	return plan, nil
}

func validateChildTargetDescriptor(keyID string, generation tssrun.KeyGeneration, epochID tssrun.EpochID) error {
	binding := tssrun.GenerationBinding{KeyID: keyID, KeyGeneration: generation, EpochID: epochID}
	if err := binding.Validate(); err != nil {
		return fmt.Errorf("invalid child target descriptor: %w", err)
	}
	return nil
}

func validateChildDerivationResult(result *tss.DerivationResult, requested tss.DerivationPath, mode tss.InvalidChildMode) error {
	if result == nil {
		return errors.New("missing child derivation result")
	}
	if err := result.Validate(); err != nil {
		return err
	}
	if result.Scheme != tss.DerivationSchemeBIP32Secp256k1 {
		return errors.New("child derivation result has wrong scheme")
	}
	if len(result.RequestedPath) == 0 || !slices.Equal(result.RequestedPath, requested) {
		return errors.New("child derivation requested path mismatch")
	}
	if !mode.Valid() {
		return fmt.Errorf("%w: %d", tss.ErrInvalidChildMode, mode)
	}
	if _, err := secp.PointFromBytes(result.ChildPublicKey); err != nil {
		return fmt.Errorf("invalid child public key: %w", err)
	}
	if _, err := secp.ScalarFromBytesAllowZero(result.AdditiveShift); err != nil {
		return fmt.Errorf("invalid child additive tweak: %w", err)
	}
	return nil
}

// ValidateWithLimits validates every public plan binding and recomputes the
// BIP32 child result and stable child SID.
func (p *ChildDerivationPlan) ValidateWithLimits(limits Limits) error {
	if p == nil || p.state == nil {
		return errors.New("nil child derivation plan")
	}
	s := p.state
	parentEpochID, err := tssrun.NewEpochID(s.ParentEpochID)
	if err != nil {
		return fmt.Errorf("invalid parent epoch id: %w", err)
	}
	parentBinding := tssrun.GenerationBinding{
		KeyID:         s.ParentKeyID,
		KeyGeneration: tssrun.KeyGeneration(s.ParentKeyGeneration),
		EpochID:       parentEpochID,
	}
	if err := parentBinding.Validate(); err != nil {
		return fmt.Errorf("invalid parent generation binding: %w", err)
	}
	if !s.ParentSID.Valid() || !s.SessionID.Valid() || !s.ChildSID.Valid() {
		return errors.New("child derivation plan contains an invalid session id")
	}
	if s.TargetKeyID == s.ParentKeyID {
		return errors.New("child key id must differ from parent key id")
	}
	if err := validateChildTargetDescriptor(s.TargetKeyID, tssrun.KeyGeneration(s.TargetKeyGeneration), parentEpochID); err != nil {
		return err
	}
	if len(s.RequestedPath) == 0 {
		return errors.New("child derivation path must be non-empty")
	}
	if err := s.RequestedPath.ValidateNonHardened(); err != nil {
		return err
	}
	if err := s.ResolvedPath.ValidateNonHardened(); err != nil {
		return err
	}
	if !s.InvalidChildMode.Valid() {
		return fmt.Errorf("%w: %d", tss.ErrInvalidChildMode, s.InvalidChildMode)
	}
	if _, err := validatePlanParties(s.Parties, s.Threshold, limits); err != nil {
		return err
	}
	if err := s.SecurityParams.Validate(); err != nil {
		return err
	}
	if s.PaillierBits < int(s.SecurityParams.MinPaillierBits) ||
		(limits.Paillier.MaxModulusBits > 0 && s.PaillierBits > limits.Paillier.MaxModulusBits) {
		return errors.New("child derivation Paillier key size is outside allowed bounds")
	}
	if _, err := secp.PointFromBytes(s.ParentPublicKey); err != nil {
		return fmt.Errorf("invalid parent public key: %w", err)
	}
	if len(s.ParentChainCode) != 32 {
		return errors.New("parent chain code must be 32 bytes")
	}
	recomputed, err := DeriveNonHardenedBIP32(
		s.ParentPublicKey,
		s.ParentChainCode,
		s.RequestedPath.Clone(),
		tss.WithInvalidChildMode(s.InvalidChildMode),
	)
	if err != nil {
		return fmt.Errorf("recompute child derivation: %w", err)
	}
	defer recomputed.Destroy()
	if err := validateChildDerivationResult(recomputed, s.RequestedPath, s.InvalidChildMode); err != nil {
		return err
	}
	if !slices.Equal(s.ResolvedPath, recomputed.ResolvedPath) ||
		!bytes.Equal(s.ChildPublicKey, recomputed.ChildPublicKey) ||
		!bytes.Equal(s.ChildChainCode, recomputed.ChildChainCode) ||
		!bytes.Equal(s.Tweak, recomputed.AdditiveShift) ||
		s.Depth != recomputed.Depth ||
		!bytes.Equal(s.ParentFingerprint, recomputed.ParentFingerprint[:]) ||
		s.ChildNumber != recomputed.ChildNumber {
		return errors.New("child derivation result does not match parent, path, and mode")
	}
	expectedSID, err := deriveChildLineageSID(s)
	if err != nil {
		return err
	}
	if expectedSID != s.ChildSID {
		return errors.New("child lineage sid mismatch")
	}
	return nil
}

func deriveChildLineageSID(s *childDerivationPlanState) (tss.SessionID, error) {
	if s == nil {
		return tss.SessionID{}, errors.New("nil child derivation plan state")
	}
	t := transcript.New(childDerivationSIDLabel)
	t.AppendString("parent_key_id", s.ParentKeyID)
	t.AppendString("parent_key_generation", s.ParentKeyGeneration)
	t.AppendBytes("parent_epoch_id", s.ParentEpochID)
	t.AppendBytes("parent_sid", s.ParentSID[:])
	t.AppendString("target_key_id", s.TargetKeyID)
	t.AppendString("target_key_generation", s.TargetKeyGeneration)
	t.AppendUint32List("requested_path", s.RequestedPath)
	t.AppendUint32List("resolved_path", s.ResolvedPath)
	t.AppendUint32("invalid_child_mode", uint32(s.InvalidChildMode))
	t.AppendBytes("parent_public_key", s.ParentPublicKey)
	t.AppendBytes("parent_chain_code", s.ParentChainCode)
	t.AppendBytes("child_public_key", s.ChildPublicKey)
	t.AppendBytes("child_chain_code", s.ChildChainCode)
	t.AppendBytes("tweak", s.Tweak)
	t.AppendUint32List("parties", s.Parties)
	t.AppendUint32("threshold", uint32(s.Threshold))
	appendSecurityParamsTranscript(t, s.SecurityParams)
	sum := t.Sum()
	var sid tss.SessionID
	copy(sid[:], sum)
	clear(sum)
	if !sid.Valid() {
		return tss.SessionID{}, errors.New("derived child lineage sid is zero")
	}
	return sid, nil
}

// Digest returns the canonical shared plan digest.
func (p *ChildDerivationPlan) Digest() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil child derivation plan")
	}
	if err := p.ValidateWithLimits(p.limits); err != nil {
		return nil, err
	}
	s := p.state
	t := transcript.New(childDerivationPlanDigestLabel)
	t.AppendString("parent_key_id", s.ParentKeyID)
	t.AppendString("parent_key_generation", s.ParentKeyGeneration)
	t.AppendBytes("parent_epoch_id", s.ParentEpochID)
	t.AppendBytes("parent_sid", s.ParentSID[:])
	t.AppendBytes("session_id", s.SessionID[:])
	t.AppendString("target_key_id", s.TargetKeyID)
	t.AppendString("target_key_generation", s.TargetKeyGeneration)
	t.AppendUint32List("requested_path", s.RequestedPath)
	t.AppendUint32List("resolved_path", s.ResolvedPath)
	t.AppendUint32("invalid_child_mode", uint32(s.InvalidChildMode))
	t.AppendBytes("parent_public_key", s.ParentPublicKey)
	t.AppendBytes("parent_chain_code", s.ParentChainCode)
	t.AppendBytes("child_public_key", s.ChildPublicKey)
	t.AppendBytes("child_chain_code", s.ChildChainCode)
	t.AppendBytes("tweak", s.Tweak)
	t.AppendUint32("depth", uint32(s.Depth))
	t.AppendBytes("parent_fingerprint", s.ParentFingerprint)
	t.AppendUint32("child_number", s.ChildNumber)
	t.AppendUint32List("parties", s.Parties)
	t.AppendUint32("threshold", uint32(s.Threshold))
	t.AppendUint32("paillier_bits", uint32(s.PaillierBits))
	appendSecurityParamsTranscript(t, s.SecurityParams)
	t.AppendBytes("child_sid", s.ChildSID[:])
	return t.Sum(), nil
}

// Snapshot returns an independently owned public plan snapshot.
func (p *ChildDerivationPlan) Snapshot() (ChildDerivationPlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return ChildDerivationPlanSnapshot{}, false
	}
	parentEpochID, err := tssrun.NewEpochID(p.state.ParentEpochID)
	if err != nil {
		return ChildDerivationPlanSnapshot{}, false
	}
	var fingerprint [4]byte
	copy(fingerprint[:], p.state.ParentFingerprint)
	return ChildDerivationPlanSnapshot{
		ParentBinding: tssrun.GenerationBinding{
			KeyID:         p.state.ParentKeyID,
			KeyGeneration: tssrun.KeyGeneration(p.state.ParentKeyGeneration),
			EpochID:       parentEpochID,
		},
		ParentSID:           p.state.ParentSID,
		SessionID:           p.state.SessionID,
		TargetKeyID:         p.state.TargetKeyID,
		TargetKeyGeneration: tssrun.KeyGeneration(p.state.TargetKeyGeneration),
		Derivation: &tss.DerivationResult{
			Scheme:            tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey:    bytes.Clone(p.state.ChildPublicKey),
			ChildChainCode:    bytes.Clone(p.state.ChildChainCode),
			RequestedPath:     p.state.RequestedPath.Clone(),
			ResolvedPath:      p.state.ResolvedPath.Clone(),
			Depth:             p.state.Depth,
			ParentFingerprint: fingerprint,
			ChildNumber:       p.state.ChildNumber,
			AdditiveShift:     bytes.Clone(p.state.Tweak),
		},
		Parties:        p.state.Parties.Clone(),
		Threshold:      p.state.Threshold,
		PaillierBits:   p.state.PaillierBits,
		SecurityParams: p.state.SecurityParams,
		ChildSID:       p.state.ChildSID,
	}, true
}

// ParentBinding returns the exact source generation bound by the plan.
func (p *ChildDerivationPlan) ParentBinding() (tssrun.GenerationBinding, bool) {
	snapshot, ok := p.Snapshot()
	return snapshot.ParentBinding, ok
}

// SessionID returns the concrete child-derivation protocol run session.
func (p *ChildDerivationPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.SessionID
}

// ChildSID returns the stable lineage SID derived for the child key.
func (p *ChildDerivationPlan) ChildSID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.ChildSID
}

// TargetDescriptor returns the distinct child key ID and generation named by
// the plan. The child EpochID is derived only after Figure 7 completes.
func (p *ChildDerivationPlan) TargetDescriptor() (string, tssrun.KeyGeneration, bool) {
	if p == nil || p.state == nil {
		return "", "", false
	}
	return p.state.TargetKeyID, tssrun.KeyGeneration(p.state.TargetKeyGeneration), true
}

// Threshold returns the child signing threshold.
func (p *ChildDerivationPlan) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.Threshold
}

func (p *ChildDerivationPlan) thresholdConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if err := p.ValidateWithLimits(p.limits); err != nil {
		return tss.ThresholdConfig{}, err
	}
	if !p.state.Parties.Contains(local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in child derivation plan")
	}
	return tss.ThresholdConfig{
		Threshold:      p.state.Threshold,
		Parties:        p.state.Parties.Clone(),
		Self:           local.Self,
		SessionID:      p.state.SessionID,
		Rand:           local.Rand,
		Context:        local.Context,
		RoundTimeout:   local.RoundTimeout,
		Log:            local.Log,
		EnvelopeSigner: local.EnvelopeSigner,
	}, nil
}

func (p *ChildDerivationPlan) validateParentKey(key *KeyShare, local tss.LocalConfig) error {
	if p == nil || p.state == nil || key == nil || key.state == nil {
		return errors.New("nil child derivation plan or parent key")
	}
	if key.state.Party != local.Self {
		return errors.New("local party does not own loaded parent key share")
	}
	if key.state.Epoch == nil ||
		!bytes.Equal(key.state.Epoch.EpochID, p.state.ParentEpochID) ||
		key.state.Epoch.SID != p.state.ParentSID ||
		key.state.Threshold != p.state.Threshold ||
		!slices.Equal(key.state.Parties, p.state.Parties) ||
		!bytes.Equal(key.state.PublicKey, p.state.ParentPublicKey) ||
		!bytes.Equal(key.state.ChainCode, p.state.ParentChainCode) ||
		key.state.SecurityParams != p.state.SecurityParams {
		return errors.New("loaded parent key does not match child derivation plan")
	}
	recomputed, err := DeriveNonHardenedBIP32(
		key.state.PublicKey,
		key.state.ChainCode,
		p.state.RequestedPath.Clone(),
		tss.WithInvalidChildMode(p.state.InvalidChildMode),
	)
	if err != nil {
		return err
	}
	defer recomputed.Destroy()
	if !slices.Equal(recomputed.ResolvedPath, p.state.ResolvedPath) ||
		!bytes.Equal(recomputed.ChildPublicKey, p.state.ChildPublicKey) ||
		!bytes.Equal(recomputed.ChildChainCode, p.state.ChildChainCode) ||
		!bytes.Equal(recomputed.AdditiveShift, p.state.Tweak) {
		return errors.New("loaded parent key derives a different child result")
	}
	return nil
}

var _ wire.Message = (*childDerivationPlanState)(nil)
