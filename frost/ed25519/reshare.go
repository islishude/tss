package ed25519

import (
	"bytes"
	"errors"
	"slices"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

const (
	payloadReshareCommitments tss.PayloadType = "frost.ed25519.reshare.commitments"
	payloadReshareShare       tss.PayloadType = "frost.ed25519.reshare.share"
)

// ReshareSession tracks a FROST key resharing exchange.
// The group public key is preserved through Lagrange-weighted constant terms.
type ReshareSession struct {
	mu           sync.Mutex
	oldKey       *KeyShare      // Caller-owned old share for dealers; nil for recipient-only participants.
	oldPublicKey publicKeyPoint // Existing parent group public key that must be preserved.
	chainCode    []byte         // Existing HD chain code that must be preserved.
	oldParties   tss.PartySet   // Canonical dealer set of old key holders.
	newParties   tss.PartySet   // Canonical target key-holder set.
	newThreshold int            // Target signing threshold.
	selfID       tss.PartyID    // Local party ID for envelope recipient/sender checks.
	mode         frostReshareMode
	role         frostReshareRole
	planHash     []byte // Digest every reshare payload must echo.

	cfg     tss.ThresholdConfig                // Local threshold runtime view for this role.
	log     tss.Logger                         // Optional protocol logger.
	limits  Limits                             // Local fail-closed resource policy.
	commits map[tss.PartyID]reshareCommitments // Public dealer polynomial commitments by dealer.
	shares  map[tss.PartyID]*secret.Scalar     // Secret dealer contributions received by this receiver.

	completed bool               // Terminal success flag after newShare is available.
	aborted   bool               // Terminal failure/destruction flag.
	newShare  *KeyShare          // New key share produced for recipient participants.
	guard     *tss.EnvelopeGuard // Transport replay, identity, and policy guard.
}

type reshareCommitmentsPayload struct {
	Commitments reshareCommitments `json:"commitments" wire:"1,custom,max_items=threshold"`
	PlanHash    []byte             `json:"plan_hash" wire:"2,bytes,len=32"`
}

const reshareCommitmentsPayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for reshareCommitmentsPayload.
func (reshareCommitmentsPayload) WireType() string { return reshareCommitmentsPayloadWireType }

// WireVersion returns the wire format version for reshareCommitmentsPayload.
func (reshareCommitmentsPayload) WireVersion() uint16 {
	return reshareCommitmentsPayloadWireVersion
}

type reshareSharePayload struct {
	Share    *secret.Scalar `json:"share" wire:"1,custom,len=32"`
	PlanHash []byte         `json:"plan_hash" wire:"2,bytes,len=32"`
}

const reshareSharePayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for reshareSharePayload.
func (reshareSharePayload) WireType() string { return reshareSharePayloadWireType }

// WireVersion returns the wire format version for reshareSharePayload.
func (reshareSharePayload) WireVersion() uint16 { return reshareSharePayloadWireVersion }

// MarshalJSON rejects default JSON encoding of secret reshare shares.
func (reshareSharePayload) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 reshare share payload must use wire encoding (MarshalBinary)")
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *ReshareSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *ReshareSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolFROSTEd25519, s.cfg.SessionID, s.oldParties, s.selfID)
}

func reshareGuardParties(oldParties, newParties tss.PartySet) tss.PartySet {
	seen := make(map[tss.PartyID]struct{}, len(oldParties)+len(newParties))
	union := make(tss.PartySet, 0, len(oldParties)+len(newParties))
	for _, id := range oldParties {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		union = append(union, id)
	}
	for _, id := range newParties {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		union = append(union, id)
	}
	return tss.SortParties(union)
}

func validateResharePlanMatchesOldKey(plan *ResharePlan, oldKey *KeyShare) error {
	if plan == nil || plan.state == nil {
		return errors.New("nil reshare plan")
	}
	if oldKey == nil || oldKey.state == nil {
		return errors.New("nil old key share")
	}
	if !plan.state.oldPublicKey.Equal(oldKey.state.publicKey) {
		return errors.New("old key public key does not match reshare plan")
	}
	if !bytes.Equal(plan.state.oldChainCode, oldKey.state.chainCode) {
		return errors.New("old key chain code does not match reshare plan")
	}
	if !slices.Equal(plan.state.oldParties, oldKey.state.parties) {
		return errors.New("old key party set does not match reshare plan")
	}
	return nil
}

// StartReshare starts a FROST key resharing as an old-party dealer.
// Each dealer computes w_i = λ_i(old,0) * old_share_i and generates a random
// polynomial with w_i as the constant term. The aggregated polynomial preserves
// the group secret while supporting arbitrary membership and threshold changes.
//
// newParties defines the target participant set and newThreshold the target
// threshold. Both may differ from the old key's parties and threshold.
//
// In production, the shared reshare plan means equivalent authenticated
// reshare-run metadata, not a shared Go object. Old parties start the dealer
// role with StartReshare, while new-only recipients use StartReshareRecipient.
func StartReshare(oldKey *KeyShare, plan *ResharePlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*ReshareSession, []tss.Envelope, error) {
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil reshare plan"))
	}
	if oldKey == nil || oldKey.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil old key share"))
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	limits := plan.limits
	if local.Self == 0 {
		local.Self = oldKey.state.party
	}
	config, err := plan.dealerConfig(local)
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if err := config.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if config.Self != oldKey.state.party {
		return nil, nil, invalidPlanConfig(config.Self, errors.New("config.Self must match the old key's party ID"))
	}
	if err := validateResharePlanMatchesOldKey(plan, oldKey); err != nil {
		return nil, nil, invalidPlanConfig(config.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolFROSTEd25519, config.SessionID, config.Self); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	oldParties := oldKey.state.parties.Clone()
	// Fix config.Parties to the old party set so blame evidence is deterministic.
	config.Parties = oldParties
	newParties := plan.state.newParties.Clone()
	newThreshold := plan.state.newThreshold
	isRecipient := tss.ContainsParty(newParties, oldKey.state.party)
	role := frostReshareRoleDealerOnly
	if isRecipient {
		role = frostReshareRoleDealerAndRecipient
	}

	// Compute w_i = λ_i(old, 0) * s_i (mod L).
	lambda, err := lagrangeCoefficientScalar(oldKey.state.party, oldParties)
	if err != nil {
		return nil, nil, err
	}
	oldSecret, err := oldKey.secretScalar()
	if err != nil {
		return nil, nil, err
	}
	defer oldSecret.Set(fed.NewScalar())
	weighted := fed.NewScalar().Multiply(lambda, oldSecret)
	defer weighted.Set(fed.NewScalar())

	prepared, err := prepareReshareDealerStart(
		oldKey,
		config,
		limits,
		planHash,
		oldParties,
		newParties,
		newThreshold,
		frostReshareModeReshare,
		role,
		weighted,
		guard,
	)
	if err != nil {
		return nil, nil, err
	}
	defer prepared.destroy()
	prepared.markCommitted()
	return prepared.session, prepared.out, nil
}

// StartReshareRecipient starts a resharing session for a new participant.
// config.Self is the recipient ID. The function validates membership against
// newParties and validates incoming dealer messages against oldParties.
//
// In production, the shared reshare plan means equivalent authenticated
// reshare-run metadata, not a shared Go object. New-only recipients use this
// entry point while old parties start the dealer role with StartReshare.
func StartReshareRecipient(plan *ResharePlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*ReshareSession, error) {
	if plan == nil || plan.state == nil {
		return nil, invalidPlanConfig(local.Self, errors.New("nil reshare plan"))
	}
	limits := plan.limits
	config, err := plan.receiverConfig(local)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if !tss.ContainsParty(plan.state.newParties, config.Self) {
		return nil, invalidPlanConfig(config.Self, errors.New("recipient must be in the new participant set"))
	}
	if tss.ContainsParty(plan.state.oldParties, config.Self) {
		return nil, invalidPlanConfig(config.Self, errors.New("recipient is in the old participant set; use StartReshare instead"))
	}
	validationConfig := config
	validationConfig.Parties = plan.state.newParties.Clone()
	validationConfig.Threshold = plan.state.newThreshold
	if err := validationConfig.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolFROSTEd25519, config.SessionID, config.Self); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	// Blame evidence for reshare share verification is scoped to old dealers.
	config.Parties = plan.state.oldParties.Clone()
	config.Threshold = len(plan.state.oldParties)
	return &ReshareSession{
		oldPublicKey: plan.state.oldPublicKey.Clone(),
		chainCode:    append([]byte(nil), plan.state.oldChainCode...),
		oldParties:   plan.state.oldParties.Clone(),
		newParties:   plan.state.newParties.Clone(),
		newThreshold: plan.state.newThreshold,
		selfID:       config.Self,
		mode:         frostReshareModeReshare,
		role:         frostReshareRoleRecipientOnly,
		cfg:          config,
		log:          config.Logger(),
		limits:       limits,
		planHash:     append([]byte(nil), planHash...),
		commits:      make(map[tss.PartyID]reshareCommitments),
		shares:       make(map[tss.PartyID]*secret.Scalar),
		guard:        guard,
	}, nil
}

// StartRefresh starts a FROST same-party proactive key refresh using the
// simpler zero-constant-term polynomial approach. The participant set and
// threshold are unchanged.
//
// In production, StartRefresh starts this party's local refresh state machine
// from equivalent authenticated refresh-run metadata. The refreshed KeyShare is
// staged output and should be installed with compare-and-swap against the
// expected current key generation.
func StartRefresh(oldKey *KeyShare, plan *RefreshPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*ReshareSession, []tss.Envelope, error) {
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil refresh plan"))
	}
	if oldKey == nil || oldKey.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil old key share"))
	}
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	limits := plan.limits
	if local.Self == 0 {
		local.Self = oldKey.state.party
	}
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if err := config.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if config.Self != oldKey.state.party {
		return nil, nil, invalidPlanConfig(config.Self, errors.New("config.Self must match the old key's party ID"))
	}
	if plan.state.threshold != oldKey.state.threshold || !plan.state.publicKey.Equal(oldKey.state.publicKey) || !bytes.Equal(plan.state.chainCode, oldKey.state.chainCode) || !slices.Equal(plan.state.parties, oldKey.state.parties) {
		return nil, nil, invalidPlanConfig(config.Self, errors.New("refresh plan does not match old key share"))
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolFROSTEd25519, config.SessionID, config.Self); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	parties := oldKey.state.parties.Clone()
	config.Parties = parties
	config.Threshold = oldKey.state.threshold
	// Zero-coefficient polynomial preserves the group secret.
	zero := fed.NewScalar()
	defer zero.Set(fed.NewScalar())
	prepared, err := prepareReshareDealerStart(
		oldKey,
		config,
		limits,
		planHash,
		parties,
		parties,
		oldKey.state.threshold,
		frostReshareModeRefresh,
		frostReshareRoleDealerAndRecipient,
		zero,
		guard,
	)
	if err != nil {
		return nil, nil, err
	}
	defer prepared.destroy()
	prepared.markCommitted()
	return prepared.session, prepared.out, nil
}

// HandleReshareMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleReshareMessage(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(base.Round, base.From)
	}
	if s.aborted {
		return nil, abortedSessionError(base.Round, base.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	tx, err := s.buildReshareTransition(env)
	if err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	defer tx.cleanupOnReject()
	effects, err := tx.apply(s)
	if err != nil {
		return nil, err
	}
	tx.markCommitted()
	return effects.envelopes, nil
}

func (s *ReshareSession) clearSensitive() {
	if s == nil {
		return
	}
	clearSecretScalarMap(s.shares)
}

// KeyShare returns the reshared key share when resharing completes.
func (s *ReshareSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed || s.newShare == nil {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}
