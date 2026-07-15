package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/tssrun"
)

const reshareCurveID = "secp256k1"

const resharePlanDigestLabel = "cggmp21-secp256k1-reshare-plan-v1"

// ResharePlan is the canonical public input agreed by old dealers and new
// receivers. Its fields are opaque; public metadata is exposed through
// caller-owned snapshots, and old-party verification shares are exposed by
// PartyID.
type ResharePlan struct {
	state  *resharePlanState
	limits Limits
}

// ResharePlanSnapshot is a caller-owned copy of reshare plan metadata.
type ResharePlanSnapshot struct {
	SessionID                 tss.SessionID
	OldPaillierProofSessionID tss.SessionID
	OldKeygenTranscriptHash   []byte
	OldPlanHash               []byte
	CurveID                   string
	OldGroupPublicKey         []byte
	OldGroupCommitments       [][]byte
	OldParties                tss.PartySet
	OldThreshold              int
	DealerParties             tss.PartySet
	NewParties                tss.PartySet
	NewThreshold              int
	ChainCode                 []byte
	PaillierBits              int
	SecurityParams            SecurityParams
	SourceEpoch               *EpochContext
	SourceEpochID             []byte
}

// Clone returns a deep copy of the reshare plan snapshot.
func (s ResharePlanSnapshot) Clone() ResharePlanSnapshot {
	return ResharePlanSnapshot{
		SessionID:                 s.SessionID,
		OldPaillierProofSessionID: s.OldPaillierProofSessionID,
		OldKeygenTranscriptHash:   bytes.Clone(s.OldKeygenTranscriptHash),
		OldPlanHash:               bytes.Clone(s.OldPlanHash),
		CurveID:                   s.CurveID,
		OldGroupPublicKey:         bytes.Clone(s.OldGroupPublicKey),
		OldGroupCommitments:       tss.CloneByteSlices(s.OldGroupCommitments),
		OldParties:                s.OldParties.Clone(),
		OldThreshold:              s.OldThreshold,
		DealerParties:             s.DealerParties.Clone(),
		NewParties:                s.NewParties.Clone(),
		NewThreshold:              s.NewThreshold,
		ChainCode:                 bytes.Clone(s.ChainCode),
		PaillierBits:              s.PaillierBits,
		SecurityParams:            s.SecurityParams,
		SourceEpoch:               s.SourceEpoch.Clone(),
		SourceEpochID:             bytes.Clone(s.SourceEpochID),
	}
}

type resharePlanState struct {
	SessionID                 tss.SessionID          `wire:"1,bytes,len=32"`                                  // Reshare protocol session; all dealer and receiver messages are scoped to it.
	CurveID                   string                 `wire:"2,string,max_bytes=curve_id"`                     // Canonical curve identifier bound into the plan digest.
	OldGroupPublicKey         []byte                 `wire:"3,bytes,max_bytes=point"`                         // Existing parent group public key that resharing must preserve.
	OldGroupCommitments       [][]byte               `wire:"4,byteslist,max_bytes=point,max_items=threshold"` // Existing public polynomial commitments for old shares.
	OldVerificationShares     map[tss.PartyID][]byte `wire:"5,map,max_items=parties,max_bytes=point"`         // Existing per-party public verification shares keyed by old party.
	OldParties                tss.PartySet           `wire:"6,u32list,max_items=parties"`                     // Canonical old key-holder set.
	OldThreshold              int                    `wire:"7,u32"`                                           // Signing threshold of the old key.
	DealerParties             tss.PartySet           `wire:"8,u32list,max_items=parties"`                     // Old parties selected to contribute weighted dealer polynomials.
	NewParties                tss.PartySet           `wire:"9,u32list,max_items=parties"`                     // Canonical target key-holder set.
	NewThreshold              int                    `wire:"10,u32"`                                          // Signing threshold for the reshared key.
	ChainCode                 []byte                 `wire:"11,bytes,len=32"`                                 // HD chain code preserved across reshare.
	PaillierBits              int                    `wire:"12,u32"`                                          // Shared modulus size for new receiver auxiliary material.
	SecurityParams            SecurityParams         `wire:"13,record"`                                       // Cryptographic profile required for new auxiliary material.
	OldPaillierProofSessionID tss.SessionID          `wire:"14,bytes,len=32"`                                 // Exact lifecycle session that produced the old key generation.
	OldKeygenTranscriptHash   []byte                 `wire:"15,bytes,len=32"`                                 // Exact transcript of the source key generation.
	OldPlanHash               []byte                 `wire:"16,bytes,len=32"`                                 // Exact lifecycle plan that produced the source key generation.
	SourceEpoch               *EpochContext          `wire:"17,record"`                                       // Exact public epoch whose dynamically identified shares are being reshared.
	SourceEpochID             []byte                 `wire:"18,bytes,len=32"`                                 // Explicit source-epoch identity; must equal SourceEpoch.EpochID.
}

// SessionID returns the reshare session identifier.
func (p *ResharePlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.SessionID
}

// CurveID returns the canonical curve identifier.
func (p *ResharePlan) CurveID() string {
	if p == nil || p.state == nil {
		return ""
	}
	return p.state.CurveID
}

// OldThreshold returns the old signing threshold.
func (p *ResharePlan) OldThreshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.OldThreshold
}

// NewThreshold returns the new signing threshold.
func (p *ResharePlan) NewThreshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.NewThreshold
}

// Snapshot returns a caller-owned reshare plan snapshot.
func (p *ResharePlan) Snapshot() (ResharePlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return ResharePlanSnapshot{}, false
	}
	return ResharePlanSnapshot{
		SessionID:                 p.state.SessionID,
		OldPaillierProofSessionID: p.state.OldPaillierProofSessionID,
		OldKeygenTranscriptHash:   bytes.Clone(p.state.OldKeygenTranscriptHash),
		OldPlanHash:               bytes.Clone(p.state.OldPlanHash),
		CurveID:                   p.state.CurveID,
		OldGroupPublicKey:         bytes.Clone(p.state.OldGroupPublicKey),
		OldGroupCommitments:       tss.CloneByteSlices(p.state.OldGroupCommitments),
		OldParties:                p.state.OldParties.Clone(),
		OldThreshold:              p.state.OldThreshold,
		DealerParties:             p.state.DealerParties.Clone(),
		NewParties:                p.state.NewParties.Clone(),
		NewThreshold:              p.state.NewThreshold,
		ChainCode:                 bytes.Clone(p.state.ChainCode),
		PaillierBits:              p.state.PaillierBits,
		SecurityParams:            p.state.SecurityParams,
		SourceEpoch:               p.state.SourceEpoch.Clone(),
		SourceEpochID:             bytes.Clone(p.state.SourceEpochID),
	}, true
}

// SourceEpoch returns a caller-owned copy of the exact source epoch.
func (p *ResharePlan) SourceEpoch() (*EpochContext, bool) {
	if p == nil || p.state == nil || p.state.SourceEpoch == nil {
		return nil, false
	}
	return p.state.SourceEpoch.Clone(), true
}

// SourceEpochID returns the immutable exact source epoch ID. The all-zero
// value reports an unavailable or invalid plan.
func (p *ResharePlan) SourceEpochID() tssrun.EpochID {
	if p == nil || p.state == nil {
		return tssrun.EpochID{}
	}
	id, err := tssrun.NewEpochID(p.state.SourceEpochID)
	if err != nil {
		return tssrun.EpochID{}
	}
	return id
}

// OldVerificationShare returns a caller-owned old verification share for party.
func (p *ResharePlan) OldVerificationShare(party tss.PartyID) (VerificationShare, bool) {
	if p == nil || p.state == nil {
		return VerificationShare{}, false
	}
	share, ok := p.state.OldVerificationShares[party]
	if !ok || len(share) == 0 {
		return VerificationShare{}, false
	}
	return VerificationShare{Party: party, PublicKey: bytes.Clone(share)}, true
}

// PaillierBits returns the shared Paillier modulus size for new receiver
// auxiliary material.
func (p *ResharePlan) PaillierBits() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.PaillierBits
}

// ReshareMessageHeader identifies one logical resharing message.
type ReshareMessageHeader struct {
	SessionID tss.SessionID
	Type      string
	Sender    tss.PartyID
	Receiver  tss.PartyID
}

// ReceiverAuxBroadcast carries fresh Paillier and Ring-Pedersen material from a new receiver.
type ReceiverAuxBroadcast struct {
	Header               ReshareMessageHeader
	PaillierPublicKey    []byte
	PaillierModulusProof []byte
	RingPedersenParams   []byte
	RingPedersenProof    []byte
	AuxiliaryProofs      [][]byte
}

// DealerCommitmentBroadcast carries one old dealer's weighted contribution commitments.
type DealerCommitmentBroadcast struct {
	Header      ReshareMessageHeader
	Commitments [][]byte
}

// DealerShareDirect carries one dealer contribution for one new receiver.
type DealerShareDirect struct {
	Header                 ReshareMessageHeader
	EncryptedShareEnvelope []byte
	DealerCommitmentHash   []byte
	AuthenticatedPlaintext []byte
}

// ReceiverShareBindingBroadcast records a new receiver's share-binding material.
type ReceiverShareBindingBroadcast struct {
	Header            ReshareMessageHeader
	VerificationShare []byte
	EncryptedShare    []byte
	ShareSchnorrProof []byte
	ShareLogStarProof []byte
}

// ReshareConfirmationBroadcast records a receiver's final resharing transcript view.
type ReshareConfirmationBroadcast struct {
	Header                    ReshareMessageHeader
	ReshareTranscriptHash     []byte
	NewGroupPublicKey         []byte
	NewGroupCommitmentsHash   []byte
	NewVerificationSharesHash []byte
	ReceiverAuxHash           []byte
	DealerCommitmentsHash     []byte
	ShareBindingsHash         []byte
}

// ReshareDealerSession is an old-party dealer-only reshare session.
type ReshareDealerSession = ReshareSession

// ReshareReceiverSession is a new-party receiver-only reshare session.
type ReshareReceiverSession = ReshareSession

// ReshareOverlapSession is a session for a party that is both old dealer and new receiver.
type ReshareOverlapSession = ReshareSession

// ResharePlanOption configures CGGMP21 reshare plan construction.
type ResharePlanOption struct {
	OldKey         *KeyShare
	SourceEpoch    *EpochContext
	SessionID      tss.SessionID
	DealerParties  tss.PartySet
	NewParties     tss.PartySet
	NewThreshold   int
	PaillierBits   int
	Limits         *Limits
	SecurityParams *SecurityParams
}

// NewResharePlan constructs a canonical plan from authenticated old key metadata.
func NewResharePlan(option ResharePlanOption) (*ResharePlan, error) {
	oldKey := option.OldKey
	limits := limitsOrDefault(option.Limits)
	if oldKey == nil {
		return nil, invalidPlanConfig(0, errors.New("nil old key share"))
	}
	var party tss.PartyID
	if oldKey.state != nil {
		party = oldKey.state.Party
	}
	if err := oldKey.ValidateWithLimits(limits); err != nil {
		return nil, invalidPlanConfig(party, fmt.Errorf("invalid old key share: %w", err))
	}
	sourceEpoch := option.SourceEpoch
	if sourceEpoch == nil {
		sourceEpoch = oldKey.state.Epoch
	}
	if sourceEpoch == nil {
		return nil, invalidPlanConfig(party, errors.New("reshare source epoch is required"))
	}
	if err := sourceEpoch.ValidateWithLimits(limits); err != nil {
		return nil, invalidPlanConfig(party, fmt.Errorf("invalid reshare source epoch: %w", err))
	}
	if oldKey.state.Epoch == nil || !epochContextsEqual(oldKey.state.Epoch, sourceEpoch, limits) {
		return nil, invalidPlanConfig(party, errors.New("reshare source epoch does not exactly match old key share"))
	}
	securityParams := securityParamsForArtifact(oldKey.state.SecurityParams, option.SecurityParams)
	if option.SecurityParams != nil && validSecurityParams(oldKey.state.SecurityParams) && oldKey.state.SecurityParams != *option.SecurityParams {
		return nil, invalidPlanConfig(party, errors.New("security params mismatch with old key share"))
	}
	if err := securityParams.Validate(); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	paillierBits := option.PaillierBits
	if paillierBits == 0 {
		paillierBits = int(securityParams.MinPaillierBits)
	}
	if paillierBits < int(securityParams.MinPaillierBits) {
		return nil, invalidPlanConfig(party, fmt.Errorf("paillier key size %d is below security parameter minimum %d", paillierBits, securityParams.MinPaillierBits))
	}
	verificationShares := make(map[tss.PartyID][]byte, len(oldKey.state.Parties))
	for _, id := range oldKey.state.Parties {
		verificationShare, ok := oldKey.verificationShare(id)
		if !ok {
			return nil, invalidPlanConfig(party, fmt.Errorf("missing verification share for party %d", id))
		}
		verificationShares[id] = bytes.Clone(verificationShare)
	}
	oldGroupCommitments, err := secp.CommitmentPointsBytes(oldKey.state.GroupCommitments)
	if err != nil {
		return nil, invalidPlanConfig(party, fmt.Errorf("invalid old group commitments: %w", err))
	}
	plan := &ResharePlan{state: &resharePlanState{
		SessionID:                 option.SessionID,
		CurveID:                   reshareCurveID,
		OldGroupPublicKey:         bytes.Clone(oldKey.state.PublicKey),
		OldGroupCommitments:       oldGroupCommitments,
		OldVerificationShares:     verificationShares,
		OldParties:                tss.SortParties(oldKey.state.Parties),
		OldThreshold:              oldKey.state.Threshold,
		DealerParties:             tss.SortParties(option.DealerParties),
		NewParties:                tss.SortParties(option.NewParties),
		NewThreshold:              option.NewThreshold,
		ChainCode:                 bytes.Clone(oldKey.state.ChainCode),
		PaillierBits:              paillierBits,
		SecurityParams:            securityParams,
		OldPaillierProofSessionID: oldKey.state.PaillierProofSessionID,
		OldKeygenTranscriptHash:   bytes.Clone(oldKey.state.KeygenTranscriptHash),
		OldPlanHash:               bytes.Clone(oldKey.state.PlanHash),
		SourceEpoch:               sourceEpoch.Clone(),
		SourceEpochID:             bytes.Clone(sourceEpoch.EpochID),
	}, limits: limits}
	if len(plan.state.DealerParties) == 0 {
		plan.state.DealerParties = plan.state.OldParties.Clone()
	}
	if err := plan.ValidateWithLimits(limits); err != nil {
		return nil, invalidPlanConfig(party, err)
	}
	return plan, nil
}

// Validate checks that a reshare plan is canonical and internally consistent
// against production limits.
func (p *ResharePlan) Validate() error {
	if p == nil || p.state == nil {
		return errors.New("nil reshare plan")
	}
	if !isProductionSecurityParams(p.state.SecurityParams) {
		return errors.New("reshare plan uses non-production security params")
	}
	return p.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks that a reshare plan is canonical and internally
// consistent against the provided Limits. It enforces hard caps on old, dealer,
// and new party sets and thresholds, and rejects configurations below the
// production minimum threshold unless explicitly allowed by the limits.
func (p *ResharePlan) ValidateWithLimits(limits Limits) error {
	if p == nil || p.state == nil {
		return errors.New("nil reshare plan")
	}
	if err := p.state.SecurityParams.Validate(); err != nil {
		return fmt.Errorf("invalid security params: %w", err)
	}
	if !p.state.SessionID.Valid() {
		return errors.New("reshare plan session id must not be zero")
	}
	if !p.state.OldPaillierProofSessionID.Valid() {
		return errors.New("reshare plan old Paillier proof session id must not be zero")
	}
	if p.state.SourceEpoch == nil {
		return errors.New("reshare source epoch is required")
	}
	if err := p.state.SourceEpoch.ValidateWithLimits(limits); err != nil {
		return fmt.Errorf("invalid reshare source epoch: %w", err)
	}
	if len(p.state.SourceEpochID) != sha256.Size || !bytes.Equal(p.state.SourceEpochID, p.state.SourceEpoch.EpochID) {
		return errors.New("reshare source epoch id does not exactly match source epoch")
	}
	if len(p.state.OldKeygenTranscriptHash) != sha256.Size {
		return errors.New("old keygen transcript hash must be 32 bytes")
	}
	if len(p.state.OldPlanHash) != sha256.Size {
		return errors.New("old lifecycle plan hash must be 32 bytes")
	}
	if p.state.CurveID != reshareCurveID {
		return fmt.Errorf("reshare plan curve id must be %q", reshareCurveID)
	}
	if _, err := secp.PointFromBytes(p.state.OldGroupPublicKey); err != nil {
		return fmt.Errorf("invalid old group public key: %w", err)
	}
	if p.state.OldThreshold <= 0 || p.state.OldThreshold > len(p.state.OldParties) {
		return errors.New("invalid old threshold")
	}
	if len(p.state.OldParties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many old parties: %d > %d", len(p.state.OldParties), limits.Threshold.MaxParties)
	}
	if p.state.OldThreshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("old threshold too large: %d > %d", p.state.OldThreshold, limits.Threshold.MaxThreshold)
	}
	if err := limits.Threshold.ValidateThreshold(p.state.OldThreshold, len(p.state.OldParties)); err != nil {
		return fmt.Errorf("old %w", err)
	}
	if p.state.NewThreshold <= 0 || p.state.NewThreshold > len(p.state.NewParties) {
		return errors.New("invalid new threshold")
	}
	if len(p.state.NewParties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many new parties: %d > %d", len(p.state.NewParties), limits.Threshold.MaxParties)
	}
	if p.state.NewThreshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("new threshold too large: %d > %d", p.state.NewThreshold, limits.Threshold.MaxThreshold)
	}
	if err := limits.Threshold.ValidateThreshold(p.state.NewThreshold, len(p.state.NewParties)); err != nil {
		return fmt.Errorf("new %w", err)
	}
	if len(p.state.OldGroupCommitments) != p.state.OldThreshold {
		return errors.New("old group commitments length must equal old threshold")
	}
	for i, commitment := range p.state.OldGroupCommitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid old group commitment %d: %w", i, err)
		}
	}
	if !bytes.Equal(p.state.OldGroupCommitments[0], p.state.OldGroupPublicKey) {
		return errors.New("old group commitment constant must equal old public key")
	}
	if err := wire.ValidateStrictSortedIDs(p.state.OldParties); err != nil {
		return fmt.Errorf("invalid old participant set: %w", err)
	}
	if p.state.SourceEpoch.Threshold != p.state.OldThreshold || len(p.state.SourceEpoch.Identifiers) != len(p.state.OldParties) {
		return errors.New("reshare source epoch threshold or party count does not match old committee")
	}
	if err := wire.ValidateStrictSortedIDs(p.state.DealerParties); err != nil {
		return fmt.Errorf("invalid dealer set: %w", err)
	}
	if len(p.state.DealerParties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many dealer parties: %d > %d", len(p.state.DealerParties), limits.Threshold.MaxParties)
	}
	if err := wire.ValidateStrictSortedIDs(p.state.NewParties); err != nil {
		return fmt.Errorf("invalid new participant set: %w", err)
	}
	if len(p.state.DealerParties) < p.state.OldThreshold {
		return errors.New("dealer set is smaller than old threshold")
	}
	for _, dealer := range p.state.DealerParties {
		if !tss.ContainsParty(p.state.OldParties, dealer) {
			return fmt.Errorf("dealer %d is not an old participant", dealer)
		}
	}
	if len(p.state.OldVerificationShares) != len(p.state.OldParties) {
		return errors.New("old verification share count must equal old party count")
	}
	for _, id := range p.state.OldParties {
		verificationShare, ok := p.state.OldVerificationShares[id]
		if !ok {
			return fmt.Errorf("missing old verification share for party %d", id)
		}
		if _, err := secp.PointFromBytes(verificationShare); err != nil {
			return fmt.Errorf("invalid old verification share for party %d: %w", id, err)
		}
		identifier, ok := p.state.SourceEpoch.Identifier(id)
		if !ok {
			return fmt.Errorf("missing source epoch identifier for party %d", id)
		}
		expected, err := evaluateEncodedCommitmentsAtIdentifier(p.state.OldGroupCommitments, identifier)
		clear(identifier)
		if err != nil {
			return fmt.Errorf("evaluate old verification share for party %d: %w", id, err)
		}
		expectedBytes, err := secp.PointBytes(expected)
		if err != nil {
			return fmt.Errorf("encode old verification share for party %d: %w", id, err)
		}
		if !bytes.Equal(expectedBytes, verificationShare) {
			return fmt.Errorf("old verification share mismatch for party %d", id)
		}
		epochShare, ok := p.state.SourceEpoch.PublicShare(id)
		if !ok || !bytes.Equal(epochShare.PublicKey, verificationShare) {
			return fmt.Errorf("source epoch public share mismatch for party %d", id)
		}
	}
	if len(p.state.ChainCode) != 32 {
		return errors.New("chain code must be 32 bytes")
	}
	if p.state.PaillierBits < int(p.state.SecurityParams.MinPaillierBits) {
		return fmt.Errorf("paillier key size %d is below security parameter minimum %d", p.state.PaillierBits, p.state.SecurityParams.MinPaillierBits)
	}
	if limits.Paillier.MaxModulusBits > 0 && p.state.PaillierBits > limits.Paillier.MaxModulusBits {
		return fmt.Errorf("paillier key size %d exceeds max %d", p.state.PaillierBits, limits.Paillier.MaxModulusBits)
	}
	return nil
}

// Digest returns a canonical hash of the complete public reshare plan.
func (p *ResharePlan) Digest() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil reshare plan")
	}
	if err := p.ValidateWithLimits(p.limits); err != nil {
		return nil, err
	}
	t := transcript.New(resharePlanDigestLabel)
	t.AppendString("protocol", string(tss.ProtocolCGGMP21Secp256k1))
	t.AppendUint32("version", uint32(tss.ProtocolVersion))
	t.AppendBytes("session_id", p.state.SessionID[:])
	t.AppendBytes("old_paillier_proof_session_id", p.state.OldPaillierProofSessionID[:])
	t.AppendBytes("old_keygen_transcript_hash", p.state.OldKeygenTranscriptHash)
	t.AppendBytes("old_lifecycle_plan_hash", p.state.OldPlanHash)
	t.AppendString("curve", p.state.CurveID)
	t.AppendBytes("old_group_public_key", p.state.OldGroupPublicKey)
	t.AppendBytesList("old_group_commitments", p.state.OldGroupCommitments)
	t.AppendUint32List("old_parties", tss.SortParties(p.state.OldParties))
	t.AppendUint32List("dealer_parties", tss.SortParties(p.state.DealerParties))
	t.AppendUint32List("new_parties", tss.SortParties(p.state.NewParties))
	t.AppendUint32("old_threshold", uint32(p.state.OldThreshold))
	t.AppendUint32("new_threshold", uint32(p.state.NewThreshold))
	t.AppendBytes("chain_code", p.state.ChainCode)
	t.AppendUint32("paillier_bits", uint32(p.state.PaillierBits))
	appendSecurityParamsTranscript(t, p.state.SecurityParams)
	sourceEpoch, err := p.state.SourceEpoch.MarshalBinaryWithLimits(p.limits)
	if err != nil {
		return nil, err
	}
	t.AppendBytes("source_epoch", sourceEpoch)
	t.AppendBytes("source_epoch_id", p.state.SourceEpochID)
	for _, id := range p.state.OldParties {
		t.AppendUint32("old_party", id)
		t.AppendBytes("old_verification_share", p.state.OldVerificationShares[id])
	}
	return t.Sum(), nil
}

func epochContextsEqual(a, b *EpochContext, limits Limits) bool {
	if a == nil || b == nil {
		return a == b
	}
	aRaw, err := a.MarshalBinaryWithLimits(limits)
	if err != nil {
		return false
	}
	bRaw, err := b.MarshalBinaryWithLimits(limits)
	return err == nil && bytes.Equal(aRaw, bRaw)
}

func evaluateEncodedCommitmentsAtIdentifier(commitments [][]byte, identifier []byte) (*secp.Point, error) {
	points := make([]*secp.Point, len(commitments))
	for i, encoded := range commitments {
		point, err := secp.PointFromBytes(encoded)
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	return evaluateCommitmentPointsAtIdentifier(points, identifier)
}

// IsDealer reports whether party is in the plan's old dealer set.
func (p *ResharePlan) IsDealer(party tss.PartyID) bool {
	return p != nil && p.state != nil && tss.ContainsParty(p.state.DealerParties, party)
}

// IsReceiver reports whether party is in the plan's new receiver set.
func (p *ResharePlan) IsReceiver(party tss.PartyID) bool {
	return p != nil && p.state != nil && tss.ContainsParty(p.state.NewParties, party)
}

// IsOverlap reports whether party is both an old dealer and a new receiver.
func (p *ResharePlan) IsOverlap(party tss.PartyID) bool {
	return p.IsDealer(party) && p.IsReceiver(party)
}
