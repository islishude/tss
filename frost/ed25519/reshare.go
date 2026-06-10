package ed25519

import (
	"errors"
	"fmt"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

const (
	payloadReshareCommitments tss.PayloadType = "frost.ed25519.reshare.commitments"
	payloadReshareShare       tss.PayloadType = "frost.ed25519.reshare.share"
)

// ReshareSession tracks a FROST key resharing exchange.
// The group public key is preserved through Lagrange-weighted constant terms.
type ReshareSession struct {
	mu           sync.Mutex
	oldKey       *KeyShare // nil for recipient-only participants
	oldPublicKey []byte    // original group public key, required for preservation checks
	chainCode    []byte
	oldParties   []tss.PartyID // sorted, the dealer set (old key holders)
	newParties   []tss.PartyID // sorted, the target participant set
	newThreshold int
	isRecipient  bool        // true when this participant receives a new share
	selfID       tss.PartyID // local party ID (for To checks)
	refreshMode  bool        // true when using zero-constant-term refresh

	cfg     tss.ThresholdConfig
	log     tss.Logger
	commits map[tss.PartyID][][]byte
	shares  map[tss.PartyID]*fed.Scalar

	completed bool
	aborted   bool
	newShare  *KeyShare
	guard     *tss.EnvelopeGuard
}

type reshareCommitmentsPayload struct {
	Commitments [][]byte `json:"commitments" wire:"1,byteslist"`
}

// WireType returns the canonical wire type identifier for reshareCommitmentsPayload.
func (reshareCommitmentsPayload) WireType() string { return reshareCommitmentsPayloadWireType }

// WireVersion returns the wire format version for reshareCommitmentsPayload.
func (reshareCommitmentsPayload) WireVersion() uint16 { return tss.Version }

type reshareSharePayload struct {
	Share []byte `json:"share" wire:"1,bytes"`
}

// WireType returns the canonical wire type identifier for reshareSharePayload.
func (reshareSharePayload) WireType() string { return reshareSharePayloadWireType }

// WireVersion returns the wire format version for reshareSharePayload.
func (reshareSharePayload) WireVersion() uint16 { return tss.Version }

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
func (s *ReshareSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	// Use old parties as the guard's party set (the dealer set is the trusted set).
	return tss.NewEnvelopeGuard(s.selfID, tss.PartySet(s.oldParties), protocol, s.cfg.SessionID, FROSTPolicies(), cache)
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
// Production deployments MUST attach a guard via SetGuard before processing messages.
func (s *ReshareSession) validateInbound(env tss.Envelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.cfg.SessionID, s.oldParties, s.selfID)
}

// StartReshare starts a FROST key resharing as an old-party dealer.
// Each dealer computes w_i = λ_i(old,0) * old_share_i and generates a random
// polynomial with w_i as the constant term. The aggregated polynomial preserves
// the group secret while supporting arbitrary membership and threshold changes.
//
// newParties defines the target participant set and newThreshold the target
// threshold. Both may differ from the old key's parties and threshold.
func StartReshare(oldKey *KeyShare, newParties []tss.PartyID, newThreshold int, config tss.ThresholdConfig) (*ReshareSession, []tss.Envelope, error) {
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, nil, err
	}
	limits := DefaultLimits()
	if err := config.ValidateWithLimits(limits); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	newParties = tss.SortParties(newParties)
	if newThreshold <= 0 || newThreshold > len(newParties) {
		return nil, nil, errors.New("invalid new threshold for reshare")
	}
	if newThreshold > limits.MaxThreshold {
		return nil, nil, fmt.Errorf("new threshold too large: %d > %d", newThreshold, limits.MaxThreshold)
	}
	if config.Self != oldKey.Party {
		return nil, nil, errors.New("config.Self must match the old key's party ID")
	}
	oldParties := append([]tss.PartyID(nil), oldKey.Parties...)
	// Fix config.Parties to the old party set so blame evidence is deterministic.
	config.Parties = oldParties
	isRecipient := tss.ContainsParty(newParties, oldKey.Party)

	// Compute w_i = λ_i(old, 0) * s_i (mod L).
	lambda, err := lagrangeCoefficientScalar(oldKey.Party, oldParties)
	if err != nil {
		return nil, nil, err
	}
	oldSecret, err := oldKey.secretScalar()
	if err != nil {
		return nil, nil, err
	}
	weighted := fed.NewScalar().Multiply(lambda, oldSecret)

	// Generate polynomial g_i of degree newThreshold-1 with constant term w_i.
	poly, err := randomScalarPolynomial(config.Reader(), newThreshold, weighted)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := fed.NewIdentityPoint().ScalarBaseMult(coeff)
		commitments[i] = point.Bytes()
	}
	s := &ReshareSession{
		oldKey:       oldKey,
		oldPublicKey: oldKey.PublicKeyBytes(),
		chainCode:    append([]byte(nil), oldKey.ChainCode...),
		oldParties:   oldParties,
		newParties:   newParties,
		newThreshold: newThreshold,
		isRecipient:  isRecipient,
		selfID:       oldKey.Party,
		cfg:          config,
		log:          config.Logger(),
		commits:      map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:       map[tss.PartyID]*fed.Scalar{oldKey.Party: evalScalarPolynomial(poly, oldKey.Party)},
	}
	commitPayload, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, nil, err
	}
	commitEnv, err := envelope(config, 1, oldKey.Party, 0, payloadReshareCommitments, commitPayload, false)
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{commitEnv}
	for _, id := range newParties {
		if id == oldKey.Party {
			continue
		}
		share := evalScalarPolynomial(poly, id)
		shareBytes := share.Bytes()
		payload, err := marshalReshareSharePayload(reshareSharePayload{Share: shareBytes})
		if err != nil {
			return nil, nil, err
		}
		shareEnv, err := envelope(config, 1, oldKey.Party, id, payloadReshareShare, payload, true)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, shareEnv)
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

// StartReshareRecipient starts a resharing session for a new participant.
// config.Self is the recipient ID. The function validates membership against
// newParties and validates incoming dealer messages against oldParties.
func StartReshareRecipient(oldPublicKey, oldChainCode []byte, oldParties, newParties []tss.PartyID, newThreshold int, config tss.ThresholdConfig) (*ReshareSession, error) {
	limits := DefaultLimits()
	if _, err := edcurve.PointFromBytes(oldPublicKey); err != nil {
		return nil, fmt.Errorf("invalid old public key: %w", err)
	}
	if len(oldChainCode) != 0 && len(oldChainCode) != 32 {
		return nil, errors.New("old chain code must be empty or 32 bytes")
	}
	oldParties = tss.SortParties(oldParties)
	newParties = tss.SortParties(newParties)
	if len(oldParties) > limits.MaxParties {
		return nil, fmt.Errorf("too many old parties: %d > %d", len(oldParties), limits.MaxParties)
	}
	if err := wire.ValidateStrictSortedIDs(oldParties); err != nil {
		return nil, fmt.Errorf("invalid old participant set: %w", err)
	}
	if newThreshold <= 0 || newThreshold > len(newParties) {
		return nil, errors.New("invalid new threshold for reshare")
	}
	if newThreshold > limits.MaxThreshold {
		return nil, fmt.Errorf("new threshold too large: %d > %d", newThreshold, limits.MaxThreshold)
	}
	if !tss.ContainsParty(newParties, config.Self) {
		return nil, errors.New("recipient must be in the new participant set")
	}
	if tss.ContainsParty(oldParties, config.Self) {
		return nil, errors.New("recipient is in the old participant set; use StartReshare instead")
	}
	validationConfig := config
	validationConfig.Parties = append([]tss.PartyID(nil), newParties...)
	validationConfig.Threshold = newThreshold
	if err := validationConfig.ValidateWithLimits(limits); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	// Blame evidence for reshare share verification is scoped to old dealers.
	config.Parties = oldParties
	config.Threshold = len(oldParties)
	return &ReshareSession{
		oldPublicKey: append([]byte(nil), oldPublicKey...),
		chainCode:    append([]byte(nil), oldChainCode...),
		oldParties:   oldParties,
		newParties:   newParties,
		newThreshold: newThreshold,
		isRecipient:  true,
		selfID:       config.Self,
		cfg:          config,
		log:          config.Logger(),
		commits:      make(map[tss.PartyID][][]byte),
		shares:       make(map[tss.PartyID]*fed.Scalar),
	}, nil
}

// StartRefresh starts a FROST same-party proactive key refresh using the
// simpler zero-constant-term polynomial approach. The participant set and
// threshold are unchanged.
func StartRefresh(oldKey *KeyShare, config tss.ThresholdConfig) (*ReshareSession, []tss.Envelope, error) {
	if err := oldKey.ValidateConsistency(); err != nil {
		return nil, nil, err
	}
	limits := DefaultLimits()
	if err := config.ValidateWithLimits(limits); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if config.Self != oldKey.Party {
		return nil, nil, errors.New("config.Self must match the old key's party ID")
	}
	parties := append([]tss.PartyID(nil), oldKey.Parties...)
	config.Parties = parties
	config.Threshold = oldKey.Threshold
	// Zero-coefficient polynomial preserves the group secret.
	zero := fed.NewScalar()
	poly, err := randomScalarPolynomial(config.Reader(), oldKey.Threshold, zero)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := fed.NewIdentityPoint().ScalarBaseMult(coeff)
		commitments[i] = point.Bytes()
	}
	s := &ReshareSession{
		oldKey:       oldKey,
		oldPublicKey: oldKey.PublicKeyBytes(),
		chainCode:    append([]byte(nil), oldKey.ChainCode...),
		oldParties:   parties,
		newParties:   parties,
		newThreshold: oldKey.Threshold,
		isRecipient:  true,
		selfID:       oldKey.Party,
		refreshMode:  true,
		cfg:          config,
		log:          config.Logger(),
		commits:      map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:       map[tss.PartyID]*fed.Scalar{oldKey.Party: evalScalarPolynomial(poly, oldKey.Party)},
	}
	commitPayload, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, nil, err
	}
	commitEnv, err := envelope(config, 1, oldKey.Party, 0, payloadReshareCommitments, commitPayload, false)
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{commitEnv}
	for _, id := range parties {
		if id == oldKey.Party {
			continue
		}
		share := evalScalarPolynomial(poly, id)
		shareBytes := share.Bytes()
		payload, err := marshalReshareSharePayload(reshareSharePayload{Share: shareBytes})
		if err != nil {
			return nil, nil, err
		}
		shareEnv, err := envelope(config, 1, oldKey.Party, id, payloadReshareShare, payload, true)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, shareEnv)
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

// HandleReshareMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleReshareMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, errors.New("reshare session is already completed")
	}
	if s.aborted {
		return nil, errors.New("reshare session is aborted")
	}
	defer func() {
		if shouldAbortSession(err) {
			s.aborted = true
			s.clearSensitive()
		}
	}()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadReshareCommitments:
		p, err := unmarshalReshareCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateReshareCommitments(p.Commitments, s.newThreshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if existing, ok := s.commits[env.From]; ok {
			if equalByteSlices(existing, p.Commitments) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting reshare commitments"))
		}
		s.commits[env.From] = p.Commitments
	case payloadReshareShare:
		p, err := unmarshalReshareSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		scalar, err := edcurve.ScalarFromCanonical(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if existing, ok := s.shares[env.From]; ok {
			if existing.Equal(scalar) == 1 {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting reshare share"))
		}
		s.shares[env.From] = scalar
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
}

func (s *ReshareSession) clearSensitive() {
	if s == nil {
		return
	}
	clearScalarMap(s.shares)
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
