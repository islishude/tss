package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const (
	payloadReshareDealerCommitments = "cggmp21.secp256k1.reshare.dealer_commitments"
	payloadReshareShare             = "cggmp21.secp256k1.reshare.share"
	payloadReshareReceiverMaterial  = "cggmp21.secp256k1.reshare.receiver_material"
	reshareCommitmentsHashLabel     = "cggmp21-secp256k1-reshare-commitments-v1"
	reshareTranscriptHashLabel      = "cggmp21-secp256k1-reshare-transcript-v1"
)

// ErrUnsupportedRefreshThresholdChange is returned when fixed-party refresh is asked to change the threshold.
var ErrUnsupportedRefreshThresholdChange = errors.New("cggmp21/secp256k1: threshold change requires StartReshare")

// ReshareSession tracks a CGGMP21 party-set-changing resharing exchange.
//
// Old parties act as dealers. Each dealer uses a polynomial whose constant is
// its old share multiplied by the Lagrange coefficient for the old dealer set,
// so summing all dealer polynomials preserves the original group secret. New
// parties, including old/new overlap parties, generate fresh Paillier and
// Ring-Pedersen material and receive a new key share.
type ReshareSession struct {
	mu sync.Mutex

	plan          ResharePlan
	oldKey        *KeyShare
	oldPublicKey  []byte
	oldChainCode  []byte
	oldParties    []tss.PartyID
	dealerParties []tss.PartyID
	newParties    []tss.PartyID
	newThreshold  int
	selfID        tss.PartyID
	isDealer      bool
	isReceiver    bool

	cfg           tss.ThresholdConfig
	log           tss.Logger
	commits       map[tss.PartyID][][]byte
	shares        map[tss.PartyID]*big.Int
	completed     bool
	aborted       bool
	newShare      *KeyShare
	confirmations map[tss.PartyID][]byte
	ownPoly       []*big.Int

	newPaillier     *pai.PrivateKey
	newPaillierPubs map[tss.PartyID]PaillierPublicShare
	newPaillierPriv []byte
	newRingPedersen map[tss.PartyID]RingPedersenPublicShare
	dealerSent      bool
	pendingShares   map[tss.PartyID]pendingReshareShare
	guard           *tss.EnvelopeGuard
}

type reshareDealerCommitmentsPayload struct {
	Commitments [][]byte `wire:"1,byteslist"`
}

// WireType returns the canonical wire type identifier for reshareDealerCommitmentsPayload.
func (reshareDealerCommitmentsPayload) WireType() string { return reshareDealerCommitmentsWireType }

// WireVersion returns the wire format version for reshareDealerCommitmentsPayload.
func (reshareDealerCommitmentsPayload) WireVersion() uint16 { return tss.Version }

type reshareReceiverMaterialPayload struct {
	PaillierPublicKey  []byte `wire:"1,bytes"`
	PaillierProof      []byte `wire:"2,bytes"`
	RingPedersenParams []byte `wire:"3,bytes"`
	RingPedersenProof  []byte `wire:"4,bytes"`
}

// WireType returns the canonical wire type identifier for reshareReceiverMaterialPayload.
func (reshareReceiverMaterialPayload) WireType() string { return reshareReceiverMaterialWireType }

// WireVersion returns the wire format version for reshareReceiverMaterialPayload.
func (reshareReceiverMaterialPayload) WireVersion() uint16 { return tss.Version }

type reshareSharePayload struct {
	Dealer               tss.PartyID `wire:"1,u32"`
	Receiver             tss.PartyID `wire:"2,u32"`
	Share                *big.Int    `wire:"3,bigpos,max_bytes=scalar"`
	DealerCommitmentHash []byte      `wire:"4,bytes"`
}

// WireType returns the canonical wire type identifier for reshareSharePayload.
func (reshareSharePayload) WireType() string { return reshareSharePayloadWireType }

// WireVersion returns the wire format version for reshareSharePayload.
func (reshareSharePayload) WireVersion() uint16 { return tss.Version }

type pendingReshareShare struct {
	payload reshareSharePayload
	raw     []byte
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *ReshareSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// SetGuard attaches an envelope guard to the session. When set, all inbound
// envelopes are validated against protocol policies, transport authentication,
// confidentiality requirements, broadcast consistency, and replay detection.
func (s *ReshareSession) SetGuard(g *tss.EnvelopeGuard) {
	if s != nil {
		s.guard = g
	}
}

// NewGuard creates an EnvelopeGuard configured for this reshare session.
// cache may be nil to use an in-memory cache suitable for testing.
// The guard party set is the union of dealers and new receivers since both
// sets may send messages during the reshare protocol.
func (s *ReshareSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	// Union of dealer parties and new parties: both sets may send envelopes.
	union := make(tss.PartySet, 0, len(s.dealerParties)+len(s.newParties))
	seen := make(map[tss.PartyID]bool)
	for _, id := range s.dealerParties {
		if !seen[id] {
			seen[id] = true
			union = append(union, id)
		}
	}
	for _, id := range s.newParties {
		if !seen[id] {
			seen[id] = true
			union = append(union, id)
		}
	}
	return tss.NewEnvelopeGuard(s.selfID, union, protocol, s.cfg.SessionID, CGGMP21Policies(), cache)
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
// The allowedParties parameter selects which participants are accepted as senders
// for this round (e.g. old parties for dealer messages, new parties for receiver messages).
// Production deployments MUST attach a guard via SetGuard before processing messages.
func (s *ReshareSession) validateInbound(env tss.Envelope, allowedParties []tss.PartyID) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.cfg.SessionID, tss.PartySet(allowedParties), s.selfID)
}

// StartReshare starts CGGMP21 resharing as an old-party dealer.
//
// The target participant set is newParties and the target threshold is
// config.Threshold. If the local old party is also in newParties, it also acts
// as a receiver and will produce a new KeyShare after all old dealers and new
// receivers contribute. Old-only parties complete without producing a new share.
func StartReshare(oldKey *KeyShare, config tss.ThresholdConfig, newParties []tss.PartyID) (*ReshareSession, []tss.Envelope, error) {
	if oldKey == nil {
		return nil, nil, errors.New("nil old key share")
	}
	if config.Self != oldKey.Party {
		return nil, nil, errors.New("config.Self must match the old key's party ID")
	}
	plan, err := NewResharePlan(oldKey, config.SessionID, oldKey.Parties, newParties, config.Threshold)
	if err != nil {
		return nil, nil, err
	}
	if tss.ContainsParty(plan.NewParties, oldKey.Party) {
		return StartReshareOverlap(oldKey, plan, config.Rand)
	}
	return StartReshareDealer(oldKey, plan, config.Rand)
}

// StartReshareDealer starts resharing for an old-party dealer.
func StartReshareDealer(oldKey *KeyShare, plan ResharePlan, rng io.Reader) (*ReshareDealerSession, []tss.Envelope, error) {
	if oldKey == nil {
		return nil, nil, errors.New("nil old key share")
	}
	return startReshareSession(oldKey, plan, oldKey.Party, rng, true, false)
}

// StartReshareReceiver starts resharing for a new-party receiver.
func StartReshareReceiver(plan ResharePlan, localParty tss.PartyID, rng io.Reader) (*ReshareReceiverSession, []tss.Envelope, error) {
	return startReshareSession(nil, plan, localParty, rng, false, true)
}

// StartReshareOverlap starts resharing for a party that is both dealer and receiver.
func StartReshareOverlap(oldKey *KeyShare, plan ResharePlan, rng io.Reader) (*ReshareOverlapSession, []tss.Envelope, error) {
	if oldKey == nil {
		return nil, nil, errors.New("nil old key share")
	}
	return startReshareSession(oldKey, plan, oldKey.Party, rng, true, true)
}

func startReshareSession(oldKey *KeyShare, plan ResharePlan, localParty tss.PartyID, rng io.Reader, dealer, receiver bool) (*ReshareSession, []tss.Envelope, error) {
	if err := plan.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, localParty, err)
	}
	if dealer {
		if oldKey == nil {
			return nil, nil, errors.New("dealer requires old key share")
		}
		if oldKey.Party != localParty {
			return nil, nil, errors.New("old key party does not match local party")
		}
		if !IsDealer(plan, localParty) {
			return nil, nil, errors.New("local party is not in dealer set")
		}
		if err := validateOldKeyMatchesResharePlan(oldKey, plan); err != nil {
			return nil, nil, err
		}
		if err := oldKey.requireMPCMaterial(); err != nil {
			return nil, nil, err
		}
	}
	if receiver && !IsReceiver(plan, localParty) {
		return nil, nil, errors.New("local party is not in new receiver set")
	}
	if !dealer && !receiver {
		return nil, nil, errors.New("reshare session requires dealer or receiver role")
	}
	config := tss.ThresholdConfig{
		Threshold: plan.NewThreshold,
		Parties:   append([]tss.PartyID(nil), plan.NewParties...),
		Self:      localParty,
		SessionID: plan.SessionID,
		Rand:      rng,
	}
	s := &ReshareSession{
		plan:            cloneResharePlan(plan),
		oldKey:          oldKey,
		oldPublicKey:    append([]byte(nil), plan.OldGroupPublicKey...),
		oldChainCode:    append([]byte(nil), plan.ChainCode...),
		oldParties:      append([]tss.PartyID(nil), plan.OldParties...),
		dealerParties:   append([]tss.PartyID(nil), plan.DealerParties...),
		newParties:      append([]tss.PartyID(nil), plan.NewParties...),
		newThreshold:    plan.NewThreshold,
		selfID:          localParty,
		isDealer:        dealer,
		isReceiver:      receiver,
		cfg:             config,
		log:             config.Logger(),
		commits:         make(map[tss.PartyID][][]byte),
		shares:          make(map[tss.PartyID]*big.Int),
		confirmations:   make(map[tss.PartyID][]byte, len(plan.NewParties)),
		newPaillierPubs: make(map[tss.PartyID]PaillierPublicShare),
		newRingPedersen: make(map[tss.PartyID]RingPedersenPublicShare),
		pendingShares:   make(map[tss.PartyID]pendingReshareShare),
	}
	if receiver {
		if err := s.initReceiverMaterial(); err != nil {
			return nil, nil, err
		}
		payload, err := marshalReshareReceiverMaterialPayload(reshareReceiverMaterialPayload{
			PaillierPublicKey:  s.newPaillierPubs[s.selfID].PublicKey,
			PaillierProof:      s.newPaillierPubs[s.selfID].Proof,
			RingPedersenParams: s.newRingPedersen[s.selfID].Params,
			RingPedersenProof:  s.newRingPedersen[s.selfID].Proof,
		})
		if err != nil {
			return nil, nil, err
		}
		receiverEnv, err := envelope(s.receiverConfig(), 1, s.selfID, 0, payloadReshareReceiverMaterial, payload, false)
		if err != nil {
			return nil, nil, err
		}
		out := []tss.Envelope{receiverEnv}
		dealerOut, err := s.maybeSendDealerMessages()
		if err != nil {
			return nil, nil, err
		}
		out = append(out, dealerOut...)
		return s, out, nil
	}
	return s, nil, nil
}

func (s *ReshareSession) dealerConfig() tss.ThresholdConfig {
	config := s.cfg
	config.Parties = append([]tss.PartyID(nil), s.dealerParties...)
	return config
}

func (s *ReshareSession) receiverConfig() tss.ThresholdConfig {
	config := s.cfg
	config.Parties = append([]tss.PartyID(nil), s.newParties...)
	config.Threshold = s.newThreshold
	return config
}

// HandleReshareMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleReshareMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		if (!s.isReceiver && env.PayloadType == payloadReshareReceiverMaterial) || env.PayloadType == payloadKeygenConfirmation {
			return nil, nil
		}
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.abort()
		}
	}()

	if env.PayloadType == payloadKeygenConfirmation {
		if err := s.validateInbound(env, s.newParties); err != nil {
			if errors.Is(err, tss.ErrDuplicateMessage) {
				return nil, tss.ErrDuplicateMessage
			}
			return nil, err
		}
		return s.handleReshareConfirmation(env)
	}

	// Validate against the appropriate party set based on payload type.
	allowedParties := s.dealerParties
	if env.PayloadType == payloadReshareReceiverMaterial {
		allowedParties = s.newParties
	}
	if err := s.validateInbound(env, allowedParties); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}

	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadReshareDealerCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare dealer commitments"))
		}
		p, err := unmarshalReshareDealerCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := s.validateDealerCommitments(env.From, p.Commitments); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		s.commits[env.From] = p.Commitments
		if pending, ok := s.pendingShares[env.From]; ok {
			if err := s.applyReshareShare(env.From, pending.payload, pending.raw); err != nil {
				return nil, err
			}
			delete(s.pendingShares, env.From)
		}
	case payloadReshareShare:
		if !s.isReceiver {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("local party is not a reshare receiver"))
		}
		p, err := unmarshalReshareSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare share"))
		}
		if _, ok := s.pendingShares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate pending reshare share"))
		}
		if _, ok := s.commits[env.From]; !ok {
			s.pendingShares[env.From] = pendingReshareShare{
				payload: cloneReshareSharePayload(p),
				raw:     append([]byte(nil), env.Payload...),
			}
			return nil, nil
		}
		if err := s.applyReshareShare(env.From, p, env.Payload); err != nil {
			return nil, err
		}
	case payloadReshareReceiverMaterial:
		if _, ok := s.newPaillierPubs[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare receiver material"))
		}
		p, err := unmarshalReshareReceiverMaterialPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := s.verifyAndStoreReceiverMaterial(env, p); err != nil {
			return nil, err
		}
		out, err = s.maybeSendDealerMessages()
		if err != nil {
			return nil, err
		}
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, err
	}
	out = append(out, completionOut...)
	return out, nil
}

func cloneReshareSharePayload(p reshareSharePayload) reshareSharePayload {
	return reshareSharePayload{
		Dealer:               p.Dealer,
		Receiver:             p.Receiver,
		Share:                new(big.Int).Set(p.Share),
		DealerCommitmentHash: append([]byte(nil), p.DealerCommitmentHash...),
	}
}

// KeyShare returns the new key share when this session is a new receiver and resharing completes.
func (s *ReshareSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed || s.newShare == nil {
		return nil, false
	}
	return s.newShare.Clone(), true
}

// Result returns the completed receiver key share.
func (s *ReshareSession) Result() (*KeyShare, error) {
	share, ok := s.KeyShare()
	if !ok {
		return nil, errors.New("reshare result is not available")
	}
	return share, nil
}

func validateOldKeyMatchesResharePlan(oldKey *KeyShare, plan ResharePlan) error {
	if oldKey.Threshold != plan.OldThreshold {
		return errors.New("old key threshold does not match reshare plan")
	}
	if !bytes.Equal(oldKey.PublicKey, plan.OldGroupPublicKey) {
		return errors.New("old key public key does not match reshare plan")
	}
	if !bytes.Equal(oldKey.ChainCode, plan.ChainCode) {
		return errors.New("old key chain code does not match reshare plan")
	}
	if !sameParties(oldKey.Parties, plan.OldParties) {
		return errors.New("old key party set does not match reshare plan")
	}
	if !sameByteSlices(oldKey.GroupCommitments, plan.OldGroupCommitments) {
		return errors.New("old key commitments do not match reshare plan")
	}
	for _, vs := range oldKey.VerificationShares {
		if !bytes.Equal(vs.PublicKey, plan.OldVerificationShares[vs.Party]) {
			return fmt.Errorf("old key verification share for party %d does not match reshare plan", vs.Party)
		}
	}
	return nil
}

func cloneResharePlan(in ResharePlan) ResharePlan {
	out := in
	out.OldGroupPublicKey = append([]byte(nil), in.OldGroupPublicKey...)
	out.OldGroupCommitments = wireutil.CloneByteSlices(in.OldGroupCommitments)
	out.OldVerificationShares = make(map[tss.PartyID][]byte, len(in.OldVerificationShares))
	for id, share := range in.OldVerificationShares {
		out.OldVerificationShares[id] = append([]byte(nil), share...)
	}
	out.OldParties = append([]tss.PartyID(nil), in.OldParties...)
	out.DealerParties = append([]tss.PartyID(nil), in.DealerParties...)
	out.NewParties = append([]tss.PartyID(nil), in.NewParties...)
	out.ChainCode = append([]byte(nil), in.ChainCode...)
	return out
}

func sameParties(a, b []tss.PartyID) bool {
	if len(a) != len(b) {
		return false
	}
	a = tss.SortParties(a)
	b = tss.SortParties(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// Destroy clears local secret material retained by the reshare session.
func (s *ReshareSession) Destroy() {
	if s == nil {
		return
	}
	s.abort()
}

func (s *ReshareSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	clearBigIntMap(s.shares)
	for id, pending := range s.pendingShares {
		pending.payload.Share = nil
		clear(pending.payload.DealerCommitmentHash)
		clear(pending.raw)
		delete(s.pendingShares, id)
	}
	for _, coeff := range s.ownPoly {
		secret.ClearBigInt(coeff)
	}
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	clear(s.newPaillierPriv)
	if s.newShare != nil {
		s.newShare.Destroy()
	}
}
