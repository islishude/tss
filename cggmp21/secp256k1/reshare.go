package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
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

// reshareDealerPartyData holds per-dealer state for a single reshare dealer participant.
type reshareDealerPartyData struct {
	commitments [][]byte
	share       *secret.Scalar
}

// reshareNewPartyData holds per-new-party state for a single reshare receiver participant.
// Auxiliary material is populated during round 1; confirmation is set during round 2.
type reshareNewPartyData struct {
	paillierPub  paillierPublicMaterial
	ringPedersen ringPedersenPublicMaterial
	confirmation *KeygenConfirmation
}

// ReshareSession tracks a CGGMP21 party-set-changing resharing exchange.
//
// Old parties act as dealers. Each dealer uses a polynomial whose constant is
// its old share multiplied by the Lagrange coefficient for the old dealer set,
// so summing all dealer polynomials preserves the original group secret. New
// parties, including old/new overlap parties, generate fresh Paillier and
// Ring-Pedersen material and receive a new key share.
type ReshareSession struct {
	mu sync.Mutex

	plan          *ResharePlan // Shared public reshare intent agreed by dealers and receivers.
	oldKey        *KeyShare    // Caller-owned old share for dealers; nil for receiver-only parties.
	oldPublicKey  []byte       // Existing parent group public key that must be preserved.
	oldChainCode  []byte       // Existing HD chain code that must be preserved.
	oldParties    tss.PartySet // Canonical old key-holder set.
	dealerParties tss.PartySet // Old parties selected to send weighted share contributions.
	newParties    tss.PartySet // Canonical target key-holder set.
	newThreshold  int          // Target signing threshold.
	selfID        tss.PartyID  // Local party ID for envelope recipient/sender checks.
	isDealer      bool         // Whether this party sends weighted dealer contributions.
	isReceiver    bool         // Whether this party receives and assembles a new share.

	cfg            tss.ThresholdConfig                     // Local threshold runtime view for the current role.
	log            tss.Logger                              // Optional protocol logger.
	limits         Limits                                  // Local fail-closed resource policy.
	securityParams SecurityParams                          // Cryptographic profile for new auxiliary material.
	planHash       []byte                                  // Digest every reshare payload must echo.
	dealerData     map[tss.PartyID]*reshareDealerPartyData // Per-dealer state keyed by dealer party.
	newPartyData   map[tss.PartyID]*reshareNewPartyData    // Per-new-party state keyed by receiver party.
	completed      bool                                    // Terminal success flag after newShare is confirmed.
	aborted        bool                                    // Terminal failure/destruction flag.
	newShare       *KeyShare                               // New key share produced for receiver participants.

	newPaillier *pai.PrivateKey    // Fresh local Paillier private key for receiver auxiliary material.
	dealerSent  bool               // Whether this dealer has already emitted commitments and shares.
	guard       *tss.EnvelopeGuard // Transport replay, identity, and policy guard.
}

type reshareDealerCommitmentsPayload struct {
	Commitments [][]byte `wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PlanHash    []byte   `wire:"2,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for reshareDealerCommitmentsPayload.
func (reshareDealerCommitmentsPayload) WireType() string { return reshareDealerCommitmentsWireType }

// WireVersion returns the wire format version for reshareDealerCommitmentsPayload.
func (reshareDealerCommitmentsPayload) WireVersion() uint16 {
	return reshareDealerCommitmentsWireVersion
}

type reshareReceiverMaterialPayload struct {
	PaillierPublicKey  pai.PublicKey            `wire:"1,nested,max_bytes=paillier_public_key"`
	PaillierProof      zkpai.ModulusProof       `wire:"2,nested,max_bytes=zk_proof"`
	RingPedersenParams zkpai.RingPedersenParams `wire:"3,nested,max_bytes=ring_pedersen_params"`
	RingPedersenProof  zkpai.RingPedersenProof  `wire:"4,nested,max_bytes=paillier_proof"`
	PlanHash           []byte                   `wire:"5,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for reshareReceiverMaterialPayload.
func (reshareReceiverMaterialPayload) WireType() string { return reshareReceiverMaterialWireType }

// WireVersion returns the wire format version for reshareReceiverMaterialPayload.
func (reshareReceiverMaterialPayload) WireVersion() uint16 {
	return reshareReceiverMaterialWireVersion
}

type reshareSharePayload struct {
	Dealer               tss.PartyID        `wire:"1,u32"`
	Receiver             tss.PartyID        `wire:"2,u32"`
	Ciphertext           []byte             `wire:"3,bytes,max_bytes=paillier_ciphertext"`
	Proof                zkpai.LogStarProof `wire:"4,nested,max_bytes=zk_proof"`
	DealerCommitmentHash []byte             `wire:"5,bytes,len=32"`
	PlanHash             []byte             `wire:"6,bytes,len=32"`
}

// Clone returns a deep copy of reshareSharePayload
func (p reshareSharePayload) Clone() reshareSharePayload {
	return reshareSharePayload{
		Dealer:               p.Dealer,
		Receiver:             p.Receiver,
		Ciphertext:           bytes.Clone(p.Ciphertext),
		Proof:                *p.Proof.Clone(),
		DealerCommitmentHash: bytes.Clone(p.DealerCommitmentHash),
		PlanHash:             bytes.Clone(p.PlanHash),
	}
}

// WireType returns the canonical wire type identifier for reshareSharePayload.
func (reshareSharePayload) WireType() string { return reshareSharePayloadWireType }

// WireVersion returns the wire format version for reshareSharePayload.
func (reshareSharePayload) WireVersion() uint16 { return reshareSharePayloadWireVersion }

// Guard returns the session's envelope guard for use by transport adapters.
func (s *ReshareSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
// The allowedParties parameter selects which participants are accepted as senders
// for this round (e.g. old parties for dealer messages, new parties for receiver messages).
func (s *ReshareSession) validateInbound(env tss.InboundEnvelope, allowedParties tss.PartySet) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, allowedParties, s.selfID)
}

// StartReshareDealer starts resharing for an old-party dealer. Production
// resharing uses one shared reshare-run metadata object, but parties start
// different local roles. Old dealers call StartReshareDealer, new-only
// receivers call StartReshareReceiver, and overlap parties call
// StartReshareOverlap when applicable.
func StartReshareDealer(oldKey *KeyShare, plan *ResharePlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*ReshareDealerSession, []tss.Envelope, error) {
	if oldKey == nil || oldKey.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil old key share"))
	}
	if local.Self == 0 {
		local.Self = oldKey.state.Party
	}
	return startReshareSession(oldKey, plan, local, true, false, guard)
}

// StartReshareReceiver starts resharing for a new-party receiver. Production
// resharing uses one shared reshare-run metadata object, but parties start
// different local roles. Old dealers call StartReshareDealer, new-only
// receivers call StartReshareReceiver, and overlap parties call
// StartReshareOverlap when applicable.
func StartReshareReceiver(plan *ResharePlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*ReshareReceiverSession, []tss.Envelope, error) {
	return startReshareSession(nil, plan, local, false, true, guard)
}

// StartReshareOverlap starts resharing for a party that is both dealer and
// receiver. Production resharing uses one shared reshare-run metadata object,
// but parties start different local roles. Old dealers call StartReshareDealer,
// new-only receivers call StartReshareReceiver, and overlap parties call
// StartReshareOverlap when applicable.
func StartReshareOverlap(oldKey *KeyShare, plan *ResharePlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*ReshareOverlapSession, []tss.Envelope, error) {
	if oldKey == nil || oldKey.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil old key share"))
	}
	if local.Self == 0 {
		local.Self = oldKey.state.Party
	}
	return startReshareSession(oldKey, plan, local, true, true, guard)
}

func startReshareSession(oldKey *KeyShare, plan *ResharePlan, local tss.LocalConfig, dealer, receiver bool, guard *tss.EnvelopeGuard) (*ReshareSession, []tss.Envelope, error) {
	localParty := local.Self
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(localParty, errors.New("nil reshare plan"))
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, plan.state.SessionID, localParty); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, localParty, err)
	}
	if err := requireLocalEnvelopeSigner(guard, local.EnvelopeSigner); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, localParty, err)
	}
	if err := plan.ValidateWithLimits(plan.limits); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, localParty, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, localParty, err)
	}
	if dealer {
		if oldKey == nil || oldKey.state == nil {
			return nil, nil, invalidPlanConfig(localParty, errors.New("dealer requires old key share"))
		}
		if oldKey.state.Party != localParty {
			return nil, nil, invalidPlanConfig(localParty, errors.New("old key party does not match local party"))
		}
		if !plan.IsDealer(localParty) {
			return nil, nil, invalidPlanConfig(localParty, errors.New("local party is not in dealer set"))
		}
		if err := validateOldKeyMatchesResharePlan(oldKey, plan); err != nil {
			return nil, nil, invalidPlanConfig(localParty, err)
		}
		if err := oldKey.requireMPCMaterial(plan.limits); err != nil {
			return nil, nil, err
		}
	}
	if receiver && !plan.IsReceiver(localParty) {
		return nil, nil, invalidPlanConfig(localParty, errors.New("local party is not in new receiver set"))
	}
	if !dealer && !receiver {
		return nil, nil, invalidPlanConfig(localParty, errors.New("reshare session requires dealer or receiver role"))
	}
	config := tss.ThresholdConfig{
		Threshold:      plan.state.NewThreshold,
		Parties:        plan.state.NewParties.Clone(),
		Self:           localParty,
		SessionID:      plan.state.SessionID,
		Rand:           local.Rand,
		Context:        local.Context,
		RoundTimeout:   local.RoundTimeout,
		Log:            local.Log,
		EnvelopeSigner: local.EnvelopeSigner,
	}
	s := &ReshareSession{
		plan:           cloneResharePlan(plan),
		oldKey:         oldKey,
		oldPublicKey:   bytes.Clone(plan.state.OldGroupPublicKey),
		oldChainCode:   bytes.Clone(plan.state.ChainCode),
		oldParties:     plan.state.OldParties.Clone(),
		dealerParties:  plan.state.DealerParties.Clone(),
		newParties:     plan.state.NewParties.Clone(),
		newThreshold:   plan.state.NewThreshold,
		selfID:         localParty,
		isDealer:       dealer,
		isReceiver:     receiver,
		cfg:            config,
		log:            config.Logger(),
		limits:         plan.limits,
		securityParams: plan.state.SecurityParams,
		planHash:       bytes.Clone(planHash),
		dealerData:     make(map[tss.PartyID]*reshareDealerPartyData),
		newPartyData:   make(map[tss.PartyID]*reshareNewPartyData),
		guard:          guard,
	}
	// Pre-initialize per-party entries so lookups never fail for valid parties.
	for _, id := range s.dealerParties {
		s.dealerData[id] = &reshareDealerPartyData{}
	}
	for _, id := range s.newParties {
		s.newPartyData[id] = &reshareNewPartyData{}
	}
	if receiver {
		if err := s.initReceiverMaterial(); err != nil {
			return nil, nil, err
		}
		selfNPD := s.newPartyData[s.selfID]
		payload, err := (reshareReceiverMaterialPayload{
			PaillierPublicKey:  *(selfNPD.paillierPub.PublicKey.Clone()),
			PaillierProof:      *(selfNPD.paillierPub.Proof.Clone()),
			RingPedersenParams: *(selfNPD.ringPedersen.Params.Clone()),
			RingPedersenProof:  *selfNPD.ringPedersen.Proof.Clone(),
			PlanHash:           s.planHash,
		}).MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, nil, err
		}
		receiverEnv, err := newEnvelope(s.receiverConfig(), reshareStartRound, s.selfID, tss.BroadcastPartyId, payloadReshareReceiverMaterial, payload)
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
	config.Parties = s.dealerParties.Clone()
	return config
}

func (s *ReshareSession) receiverConfig() tss.ThresholdConfig {
	config := s.cfg
	config.Parties = s.newParties.Clone()
	config.Threshold = s.newThreshold
	return config
}

// Handle validates and applies one reshare envelope.
func (s *ReshareSession) Handle(in tss.InboundEnvelope) (out []tss.Envelope, err error) {
	env := in.Envelope()
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	allowedParties := s.dealerParties
	if env.PayloadType == payloadReshareReceiverMaterial || env.PayloadType == payloadKeygenConfirmation {
		allowedParties = s.newParties
	}
	if err := s.validateInbound(in, allowedParties); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
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
		err = bindInboundAuthenticationEvidence(err, in)
		if shouldAbortSession(err) {
			s.abort()
		}
	}()

	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleReshareConfirmation(env)
	}
	switch env.PayloadType {
	case payloadReshareDealerCommitments:
		if env.Round != reshareStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare dealer commitments in wrong round"))
		}
		dd, ok := s.dealerData[env.From]
		if !ok {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("party %d is not a dealer", env.From))
		}
		if dd.commitments != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare dealer commitments"))
		}
		p, err := tss.DecodeBinaryValueWithLimits[reshareDealerCommitmentsPayload](env.Payload, s.limits)
		if err != nil {
			return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindReshareCommitment,
				"malformed reshare dealer commitments", tss.NewPartySet(env.From), err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.dealerParties, partySetHashLabel)),
				hashEvidenceField("reshare_commitment_payload_hash", env.Payload))
		}
		if err := requirePlanHash("reshare", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if err := s.validateDealerCommitments(env.From, p.Commitments); err != nil {
			return nil, verificationErrorWithEvidence(env, tss.EvidenceKindReshareCommitment,
				"invalid reshare dealer commitments", tss.NewPartySet(env.From), err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.dealerParties, partySetHashLabel)),
				rawEvidenceField(evidenceFieldCommitmentsHash, transcript.ByteSlicesHash(reshareCommitmentsHashLabel, p.Commitments)))
		}
		dd.commitments = p.Commitments
	case payloadReshareShare:
		if env.Round != reshareShareRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare encrypted share in wrong round"))
		}
		if !s.isReceiver {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("local party is not a reshare receiver"))
		}
		p, err := tss.DecodeBinaryValueWithLimits[reshareSharePayload](env.Payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := requirePlanHash("reshare", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		dd, ok := s.dealerData[env.From]
		if !ok {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("party %d is not a dealer", env.From))
		}
		if dd.share != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare share"))
		}
		if dd.commitments == nil {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare share arrived before dealer commitments"))
		}
		if err := s.applyReshareShare(env, p); err != nil {
			return nil, err
		}
	case payloadReshareReceiverMaterial:
		if env.Round != reshareStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare receiver material in wrong round"))
		}
		npd, ok := s.newPartyData[env.From]
		if !ok {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("party %d is not a new party", env.From))
		}
		if npd.paillierPub.PublicKey != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare receiver material"))
		}
		p, err := tss.DecodeBinaryValueWithLimits[reshareReceiverMaterialPayload](env.Payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := requirePlanHash("reshare", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
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

// KeyShare returns the new key share when this session is a new receiver and resharing completes.
func (s *ReshareSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed || s.aborted || s.newShare == nil {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}

// Result returns the completed receiver key share.
func (s *ReshareSession) Result() (*KeyShare, error) {
	share, ok := s.KeyShare()
	if !ok {
		return nil, errors.New("reshare result is not available")
	}
	return share, nil
}

func validateOldKeyMatchesResharePlan(oldKey *KeyShare, plan *ResharePlan) error {
	if plan == nil || plan.state == nil {
		return errors.New("nil reshare plan")
	}
	if oldKey.state.Threshold != plan.state.OldThreshold {
		return errors.New("old key threshold does not match reshare plan")
	}
	if !bytes.Equal(oldKey.state.PublicKey, plan.state.OldGroupPublicKey) {
		return errors.New("old key public key does not match reshare plan")
	}
	if !bytes.Equal(oldKey.state.ChainCode, plan.state.ChainCode) {
		return errors.New("old key chain code does not match reshare plan")
	}
	if !sameParties(oldKey.state.Parties, plan.state.OldParties) {
		return errors.New("old key party set does not match reshare plan")
	}
	oldGroupCommitments, err := secp.CommitmentPointsBytes(oldKey.state.GroupCommitments)
	if err != nil {
		return fmt.Errorf("old key commitments are invalid: %w", err)
	}
	if !sameByteSlices(oldGroupCommitments, plan.state.OldGroupCommitments) {
		return errors.New("old key commitments do not match reshare plan")
	}
	for _, id := range oldKey.state.Parties {
		verificationShare, ok := oldKey.verificationShare(id)
		if !ok || !bytes.Equal(verificationShare, plan.state.OldVerificationShares[id]) {
			return fmt.Errorf("old key verification share for party %d does not match reshare plan", id)
		}
	}
	return nil
}

func cloneResharePlan(in *ResharePlan) *ResharePlan {
	if in == nil || in.state == nil {
		return nil
	}
	out := &ResharePlan{state: &resharePlanState{
		SessionID:           in.state.SessionID,
		CurveID:             in.state.CurveID,
		OldGroupPublicKey:   bytes.Clone(in.state.OldGroupPublicKey),
		OldGroupCommitments: tss.CloneByteSlices(in.state.OldGroupCommitments),
		OldParties:          in.state.OldParties.Clone(),
		OldThreshold:        in.state.OldThreshold,
		DealerParties:       in.state.DealerParties.Clone(),
		NewParties:          in.state.NewParties.Clone(),
		NewThreshold:        in.state.NewThreshold,
		ChainCode:           bytes.Clone(in.state.ChainCode),
		PaillierBits:        in.state.PaillierBits,
		SecurityParams:      in.state.SecurityParams,
	}, limits: in.limits}
	out.state.OldVerificationShares = make(map[tss.PartyID][]byte, len(in.state.OldVerificationShares))
	for id, share := range in.state.OldVerificationShares {
		out.state.OldVerificationShares[id] = bytes.Clone(share)
	}
	return out
}

func sameParties(a, b tss.PartySet) bool {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abort()
}

func (s *ReshareSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	for _, dd := range s.dealerData {
		if dd.share != nil {
			dd.share.Destroy()
			dd.share = nil
		}
	}
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	if s.newShare != nil {
		s.newShare.Destroy()
		s.newShare = nil
	}
	s.completed = false
}

// allReshareDealerDataReceived returns true when every dealer has submitted commitments and a share.
func (s *ReshareSession) allReshareDealerDataReceived() bool {
	for _, id := range s.dealerParties {
		dd := s.dealerData[id]
		if dd == nil || dd.commitments == nil || dd.share == nil {
			return false
		}
	}
	return true
}

// allReshareReceiverMaterialReceived returns true when every new party has submitted auxiliary material.
func (s *ReshareSession) allReshareReceiverMaterialReceived() bool {
	for _, id := range s.newParties {
		npd := s.newPartyData[id]
		if npd == nil || npd.paillierPub.PublicKey == nil || npd.paillierPub.Proof == nil ||
			npd.ringPedersen.Params == nil || npd.ringPedersen.Proof == nil {
			return false
		}
	}
	return true
}

// allReshareConfirmationsReceived returns true when every new party has submitted a confirmation.
func (s *ReshareSession) allReshareConfirmationsReceived() bool {
	for _, id := range s.newParties {
		npd := s.newPartyData[id]
		if npd == nil || npd.confirmation == nil {
			return false
		}
	}
	return true
}
