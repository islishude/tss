package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const reshareCurveID = "secp256k1"

const resharePlanDigestLabel = "cggmp21-secp256k1-reshare-plan-v1"

// ResharePlan is the canonical public input agreed by old dealers and new
// receivers. Its fields are opaque; collection accessors return caller-owned
// deep copies.
type ResharePlan struct {
	state  *resharePlanState
	limits Limits
}

type resharePlanState struct {
	sessionID             tss.SessionID
	curveID               string
	oldGroupPublicKey     []byte
	oldGroupCommitments   [][]byte
	oldVerificationShares map[tss.PartyID][]byte
	oldParties            []tss.PartyID
	oldThreshold          int
	dealerParties         []tss.PartyID
	newParties            []tss.PartyID
	newThreshold          int
	chainCode             []byte
	paillierBits          int
	securityParams        SecurityParams
}

// SessionID returns the reshare session identifier.
func (p *ResharePlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.sessionID
}

// CurveID returns the canonical curve identifier.
func (p *ResharePlan) CurveID() string {
	if p == nil || p.state == nil {
		return ""
	}
	return p.state.curveID
}

// OldGroupPublicKeyBytes returns a copy of the old group public key.
func (p *ResharePlan) OldGroupPublicKeyBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return append([]byte(nil), p.state.oldGroupPublicKey...)
}

// OldGroupCommitments returns a deep copy of the old group commitments.
func (p *ResharePlan) OldGroupCommitments() [][]byte {
	if p == nil || p.state == nil {
		return nil
	}
	return wireutil.CloneByteSlices(p.state.oldGroupCommitments)
}

// OldVerificationShares returns a deep copy of the old verification-share map.
func (p *ResharePlan) OldVerificationShares() map[tss.PartyID][]byte {
	if p == nil || p.state == nil {
		return nil
	}
	out := make(map[tss.PartyID][]byte, len(p.state.oldVerificationShares))
	for id, share := range p.state.oldVerificationShares {
		out[id] = append([]byte(nil), share...)
	}
	return out
}

// OldParties returns a copy of the old participant set.
func (p *ResharePlan) OldParties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return append([]tss.PartyID(nil), p.state.oldParties...)
}

// OldThreshold returns the old signing threshold.
func (p *ResharePlan) OldThreshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.oldThreshold
}

// DealerParties returns a copy of the selected old dealer set.
func (p *ResharePlan) DealerParties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return append([]tss.PartyID(nil), p.state.dealerParties...)
}

// NewParties returns a copy of the new participant set.
func (p *ResharePlan) NewParties() []tss.PartyID {
	if p == nil || p.state == nil {
		return nil
	}
	return append([]tss.PartyID(nil), p.state.newParties...)
}

// NewThreshold returns the new signing threshold.
func (p *ResharePlan) NewThreshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.newThreshold
}

// ChainCodeBytes returns a copy of the preserved HD chain code.
func (p *ResharePlan) ChainCodeBytes() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	return append([]byte(nil), p.state.chainCode...)
}

// PaillierBits returns the shared Paillier modulus size for new receiver
// auxiliary material.
func (p *ResharePlan) PaillierBits() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.paillierBits
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
	SessionID      tss.SessionID
	DealerParties  []tss.PartyID
	NewParties     []tss.PartyID
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
		party = oldKey.state.party
	}
	if err := oldKey.ValidateWithLimits(limits); err != nil {
		return nil, invalidPlanConfig(party, fmt.Errorf("invalid old key share: %w", err))
	}
	securityParams := securityParamsForArtifact(oldKey.state.securityParams, option.SecurityParams)
	if option.SecurityParams != nil && validSecurityParams(oldKey.state.securityParams) && oldKey.state.securityParams != *option.SecurityParams {
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
	verificationShares := make(map[tss.PartyID][]byte, len(oldKey.state.verificationShares))
	for _, vs := range oldKey.state.verificationShares {
		verificationShares[vs.Party] = append([]byte(nil), vs.PublicKey...)
	}
	plan := &ResharePlan{state: &resharePlanState{
		sessionID:             option.SessionID,
		curveID:               reshareCurveID,
		oldGroupPublicKey:     append([]byte(nil), oldKey.state.publicKey...),
		oldGroupCommitments:   wireutil.CloneByteSlices(oldKey.state.groupCommitments),
		oldVerificationShares: verificationShares,
		oldParties:            tss.SortParties(oldKey.state.parties),
		oldThreshold:          oldKey.state.threshold,
		dealerParties:         tss.SortParties(option.DealerParties),
		newParties:            tss.SortParties(option.NewParties),
		newThreshold:          option.NewThreshold,
		chainCode:             append([]byte(nil), oldKey.state.chainCode...),
		paillierBits:          paillierBits,
		securityParams:        securityParams,
	}, limits: limits}
	if len(plan.state.dealerParties) == 0 {
		plan.state.dealerParties = append([]tss.PartyID(nil), plan.state.oldParties...)
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
	if !isProductionSecurityParams(p.state.securityParams) {
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
	if err := p.state.securityParams.Validate(); err != nil {
		return fmt.Errorf("invalid security params: %w", err)
	}
	if p.state.sessionID == (tss.SessionID{}) {
		return errors.New("reshare plan session id must not be zero")
	}
	if p.state.curveID != reshareCurveID {
		return fmt.Errorf("reshare plan curve id must be %q", reshareCurveID)
	}
	if _, err := secp.PointFromBytes(p.state.oldGroupPublicKey); err != nil {
		return fmt.Errorf("invalid old group public key: %w", err)
	}
	if p.state.oldThreshold <= 0 || p.state.oldThreshold > len(p.state.oldParties) {
		return errors.New("invalid old threshold")
	}
	if len(p.state.oldParties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many old parties: %d > %d", len(p.state.oldParties), limits.Threshold.MaxParties)
	}
	if p.state.oldThreshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("old threshold too large: %d > %d", p.state.oldThreshold, limits.Threshold.MaxThreshold)
	}
	if err := limits.Threshold.ValidateThreshold(p.state.oldThreshold, len(p.state.oldParties)); err != nil {
		return fmt.Errorf("old %w", err)
	}
	if p.state.newThreshold <= 0 || p.state.newThreshold > len(p.state.newParties) {
		return errors.New("invalid new threshold")
	}
	if len(p.state.newParties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many new parties: %d > %d", len(p.state.newParties), limits.Threshold.MaxParties)
	}
	if p.state.newThreshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("new threshold too large: %d > %d", p.state.newThreshold, limits.Threshold.MaxThreshold)
	}
	if err := limits.Threshold.ValidateThreshold(p.state.newThreshold, len(p.state.newParties)); err != nil {
		return fmt.Errorf("new %w", err)
	}
	if len(p.state.oldGroupCommitments) != p.state.oldThreshold {
		return errors.New("old group commitments length must equal old threshold")
	}
	for i, commitment := range p.state.oldGroupCommitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid old group commitment %d: %w", i, err)
		}
	}
	if !bytes.Equal(p.state.oldGroupCommitments[0], p.state.oldGroupPublicKey) {
		return errors.New("old group commitment constant must equal old public key")
	}
	if err := wire.ValidateStrictSortedIDs(p.state.oldParties); err != nil {
		return fmt.Errorf("invalid old participant set: %w", err)
	}
	if err := wire.ValidateStrictSortedIDs(p.state.dealerParties); err != nil {
		return fmt.Errorf("invalid dealer set: %w", err)
	}
	if len(p.state.dealerParties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many dealer parties: %d > %d", len(p.state.dealerParties), limits.Threshold.MaxParties)
	}
	if err := wire.ValidateStrictSortedIDs(p.state.newParties); err != nil {
		return fmt.Errorf("invalid new participant set: %w", err)
	}
	if len(p.state.dealerParties) < p.state.oldThreshold {
		return errors.New("dealer set is smaller than old threshold")
	}
	for _, dealer := range p.state.dealerParties {
		if !tss.ContainsParty(p.state.oldParties, dealer) {
			return fmt.Errorf("dealer %d is not an old participant", dealer)
		}
	}
	if len(p.state.oldVerificationShares) != len(p.state.oldParties) {
		return errors.New("old verification share count must equal old party count")
	}
	for _, id := range p.state.oldParties {
		verificationShare, ok := p.state.oldVerificationShares[id]
		if !ok {
			return fmt.Errorf("missing old verification share for party %d", id)
		}
		if _, err := secp.PointFromBytes(verificationShare); err != nil {
			return fmt.Errorf("invalid old verification share for party %d: %w", id, err)
		}
		expected, err := secp.EvalCommitments(p.state.oldGroupCommitments, id)
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
	}
	if len(p.state.chainCode) != 32 {
		return errors.New("chain code must be 32 bytes")
	}
	if p.state.paillierBits < int(p.state.securityParams.MinPaillierBits) {
		return fmt.Errorf("paillier key size %d is below security parameter minimum %d", p.state.paillierBits, p.state.securityParams.MinPaillierBits)
	}
	if limits.Paillier.MaxModulusBits > 0 && p.state.paillierBits > limits.Paillier.MaxModulusBits {
		return fmt.Errorf("paillier key size %d exceeds max %d", p.state.paillierBits, limits.Paillier.MaxModulusBits)
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
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendBytes("session_id", p.state.sessionID[:])
	t.AppendString("curve", p.state.curveID)
	t.AppendBytes("old_group_public_key", p.state.oldGroupPublicKey)
	t.AppendBytesList("old_group_commitments", p.state.oldGroupCommitments)
	t.AppendUint32List("old_parties", tss.SortParties(p.state.oldParties))
	t.AppendUint32List("dealer_parties", tss.SortParties(p.state.dealerParties))
	t.AppendUint32List("new_parties", tss.SortParties(p.state.newParties))
	t.AppendUint32("old_threshold", uint32(p.state.oldThreshold))
	t.AppendUint32("new_threshold", uint32(p.state.newThreshold))
	t.AppendBytes("chain_code", p.state.chainCode)
	t.AppendUint32("paillier_bits", uint32(p.state.paillierBits))
	appendSecurityParamsTranscript(t, p.state.securityParams)
	for _, id := range p.state.oldParties {
		t.AppendUint32("old_party", id)
		t.AppendBytes("old_verification_share", p.state.oldVerificationShares[id])
	}
	return t.Sum(), nil
}

// IsDealer reports whether party is in the plan's old dealer set.
func (p *ResharePlan) IsDealer(party tss.PartyID) bool {
	return p != nil && p.state != nil && tss.ContainsParty(p.state.dealerParties, party)
}

// IsReceiver reports whether party is in the plan's new receiver set.
func (p *ResharePlan) IsReceiver(party tss.PartyID) bool {
	return p != nil && p.state != nil && tss.ContainsParty(p.state.newParties, party)
}

// IsOverlap reports whether party is both an old dealer and a new receiver.
func (p *ResharePlan) IsOverlap(party tss.PartyID) bool {
	return p.IsDealer(party) && p.IsReceiver(party)
}
