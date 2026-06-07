package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const reshareCurveID = "secp256k1"

// ResharePlan is the canonical public input agreed by old dealers and new receivers.
type ResharePlan struct {
	SessionID             tss.SessionID
	CurveID               string
	OldGroupPublicKey     []byte
	OldGroupCommitments   [][]byte
	OldVerificationShares map[tss.PartyID][]byte
	OldParties            []tss.PartyID
	OldThreshold          int
	DealerParties         []tss.PartyID
	NewParties            []tss.PartyID
	NewThreshold          int
	ChainCode             []byte
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

// IncomingMessage is the transport envelope accepted by reshare sessions.
type IncomingMessage = tss.Envelope

// OutgoingMessage is the transport envelope emitted by reshare sessions.
type OutgoingMessage = tss.Envelope

// ReshareDealerSession is an old-party dealer-only reshare session.
type ReshareDealerSession = ReshareSession

// ReshareReceiverSession is a new-party receiver-only reshare session.
type ReshareReceiverSession = ReshareSession

// ReshareOverlapSession is a session for a party that is both old dealer and new receiver.
type ReshareOverlapSession = ReshareSession

// NewResharePlan constructs a canonical plan from authenticated old key metadata.
func NewResharePlan(oldKey *KeyShare, sessionID tss.SessionID, dealerParties, newParties []tss.PartyID, newThreshold int) (ResharePlan, error) {
	if oldKey == nil {
		return ResharePlan{}, errors.New("nil old key share")
	}
	if err := oldKey.Validate(); err != nil {
		return ResharePlan{}, fmt.Errorf("invalid old key share: %w", err)
	}
	verificationShares := make(map[tss.PartyID][]byte, len(oldKey.VerificationShares))
	for _, vs := range oldKey.VerificationShares {
		verificationShares[vs.Party] = append([]byte(nil), vs.PublicKey...)
	}
	plan := ResharePlan{
		SessionID:             sessionID,
		CurveID:               reshareCurveID,
		OldGroupPublicKey:     append([]byte(nil), oldKey.PublicKey...),
		OldGroupCommitments:   cloneKeyShareByteSlices(oldKey.GroupCommitments),
		OldVerificationShares: verificationShares,
		OldParties:            tss.SortParties(oldKey.Parties),
		OldThreshold:          oldKey.Threshold,
		DealerParties:         tss.SortParties(dealerParties),
		NewParties:            tss.SortParties(newParties),
		NewThreshold:          newThreshold,
		ChainCode:             append([]byte(nil), oldKey.ChainCode...),
	}
	if len(plan.DealerParties) == 0 {
		plan.DealerParties = append([]tss.PartyID(nil), plan.OldParties...)
	}
	if err := plan.Validate(); err != nil {
		return ResharePlan{}, err
	}
	return plan, nil
}

// Validate checks that a reshare plan is canonical and internally consistent.
func (p ResharePlan) Validate() error {
	if p.SessionID == (tss.SessionID{}) {
		return errors.New("reshare plan session id must not be zero")
	}
	if p.CurveID != reshareCurveID {
		return fmt.Errorf("reshare plan curve id must be %q", reshareCurveID)
	}
	if _, err := secp.PointFromBytes(p.OldGroupPublicKey); err != nil {
		return fmt.Errorf("invalid old group public key: %w", err)
	}
	if p.OldThreshold <= 0 || p.OldThreshold > len(p.OldParties) {
		return errors.New("invalid old threshold")
	}
	if p.NewThreshold <= 0 || p.NewThreshold > len(p.NewParties) {
		return errors.New("invalid new threshold")
	}
	if len(p.OldGroupCommitments) != p.OldThreshold {
		return errors.New("old group commitments length must equal old threshold")
	}
	for i, commitment := range p.OldGroupCommitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid old group commitment %d: %w", i, err)
		}
	}
	if !bytes.Equal(p.OldGroupCommitments[0], p.OldGroupPublicKey) {
		return errors.New("old group commitment constant must equal old public key")
	}
	if err := wire.ValidateStrictSortedIDs(p.OldParties); err != nil {
		return fmt.Errorf("invalid old participant set: %w", err)
	}
	if err := wire.ValidateStrictSortedIDs(p.DealerParties); err != nil {
		return fmt.Errorf("invalid dealer set: %w", err)
	}
	if err := wire.ValidateStrictSortedIDs(p.NewParties); err != nil {
		return fmt.Errorf("invalid new participant set: %w", err)
	}
	if len(p.DealerParties) < p.OldThreshold {
		return errors.New("dealer set is smaller than old threshold")
	}
	for _, dealer := range p.DealerParties {
		if !tss.ContainsParty(p.OldParties, dealer) {
			return fmt.Errorf("dealer %d is not an old participant", dealer)
		}
	}
	if len(p.OldVerificationShares) != len(p.OldParties) {
		return errors.New("old verification share count must equal old party count")
	}
	for _, id := range p.OldParties {
		verificationShare, ok := p.OldVerificationShares[id]
		if !ok {
			return fmt.Errorf("missing old verification share for party %d", id)
		}
		if _, err := secp.PointFromBytes(verificationShare); err != nil {
			return fmt.Errorf("invalid old verification share for party %d: %w", id, err)
		}
		expected, err := secp.EvalCommitments(p.OldGroupCommitments, uint32(id))
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
	if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
		return errors.New("chain code must be empty or 32 bytes")
	}
	return nil
}

// IsDealer reports whether party is in the plan's old dealer set.
func IsDealer(plan ResharePlan, party tss.PartyID) bool {
	return tss.ContainsParty(plan.DealerParties, party)
}

// IsReceiver reports whether party is in the plan's new receiver set.
func IsReceiver(plan ResharePlan, party tss.PartyID) bool {
	return tss.ContainsParty(plan.NewParties, party)
}

// IsOverlap reports whether party is both an old dealer and a new receiver.
func IsOverlap(plan ResharePlan, party tss.PartyID) bool {
	return IsDealer(plan, party) && IsReceiver(plan, party)
}
