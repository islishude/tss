package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

// KeygenSession tracks dealerless FROST DKG state for one local party.
type KeygenSession struct {
	mu             sync.Mutex
	cfg            tss.ThresholdConfig
	log            tss.Logger
	commits        map[tss.PartyID][][]byte
	shares         map[tss.PartyID]*fed.Scalar
	chainCodes     map[tss.PartyID][]byte
	chainCodeComms map[tss.PartyID][]byte
	enableHD       bool
	completed      bool
	aborted        bool
	pending        *KeyShare
	confirmations  map[tss.PartyID][]byte
	keyShare       *KeyShare
	ownPoly        []*fed.Scalar
	ownMessages    []tss.Envelope
	guard          *tss.EnvelopeGuard
}

type keygenCommitmentsPayload struct {
	Commitments     [][]byte `json:"commitments"`
	ChainCodeCommit []byte   `json:"chain_code_commit,omitempty"`
}

type keygenSharePayload struct {
	Share []byte `json:"share"`
}

// StartKeygen starts dealerless DKG and returns outbound round-one envelopes.
func StartKeygen(config tss.ThresholdConfig) (*KeygenSession, []tss.Envelope, error) {
	return StartKeygenWithOptions(config, KeygenOptions{})
}

// StartKeygenWithOptions starts dealerless DKG with optional HD chain code generation.
func StartKeygenWithOptions(config tss.ThresholdConfig, opts KeygenOptions) (*KeygenSession, []tss.Envelope, error) {
	if err := config.ValidateWithLimits(DefaultLimits()); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	parties := config.SortedParties()
	config.Parties = parties
	poly, err := randomScalarPolynomial(config.Reader(), config.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		// Each coefficient commitment lets receivers validate their private share.
		point := fed.NewIdentityPoint().ScalarBaseMult(coeff)
		commitments[i] = point.Bytes()
	}
	var chainCode []byte
	var chainCodeCommit []byte
	if opts.EnableHD {
		chainCode = make([]byte, 32)
		if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
			return nil, nil, err
		}
		chainCodeCommit = chainCodeCommitment(config.SessionID, config.Self, chainCode)
	}
	s := &KeygenSession{
		cfg:     config,
		log:     config.Logger(),
		commits: map[tss.PartyID][][]byte{config.Self: commitments},
		shares:  map[tss.PartyID]*fed.Scalar{config.Self: evalScalarPolynomial(poly, config.Self)},
		chainCodes: map[tss.PartyID][]byte{
			config.Self: append([]byte(nil), chainCode...),
		},
		enableHD: opts.EnableHD,
		chainCodeComms: map[tss.PartyID][]byte{
			config.Self: append([]byte(nil), chainCodeCommit...),
		},
		confirmations: make(map[tss.PartyID][]byte, len(parties)),
		ownPoly:       poly,
	}

	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := marshalKeygenCommitmentsPayload(keygenCommitmentsPayload{Commitments: commitments, ChainCodeCommit: chainCodeCommit})
	if err != nil {
		return nil, nil, err
	}
	out = append(out, envelope(config, 1, config.Self, 0, payloadKeygenCommitments, commitPayload, false))
	for _, id := range parties {
		if id == config.Self {
			continue
		}
		share := evalScalarPolynomial(poly, id)
		shareBytes := share.Bytes()
		payload, err := marshalKeygenSharePayload(keygenSharePayload{Share: shareBytes})
		if err != nil {
			return nil, nil, err
		}
		// Shamir shares are secret-bearing and must be delivered over a confidential transport.
		out = append(out, envelope(config, 1, config.Self, id, payloadKeygenShare, payload, true))
	}
	s.ownMessages = append([]tss.Envelope(nil), out...)
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
	return s, out, nil
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *KeygenSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// SetGuard attaches an envelope guard to the session. When set, all inbound
// envelopes are validated against protocol policies, transport authentication,
// confidentiality requirements, broadcast consistency, and replay detection.
func (s *KeygenSession) SetGuard(g *tss.EnvelopeGuard) {
	if s != nil {
		s.guard = g
	}
}

// NewGuard creates an EnvelopeGuard configured for this keygen session from the
// production FROST policy set. cache may be nil to use an in-memory cache
// suitable for testing; production deployments must supply a durable ReplayCache.
func (s *KeygenSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	return tss.NewEnvelopeGuard(s.cfg.Self, tss.PartySet(s.cfg.Parties), protocol, s.cfg.SessionID, FROSTPolicies, cache)
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
// Production deployments MUST attach a guard via SetGuard before processing messages.
func (s *KeygenSession) validateInbound(env tss.Envelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self, FROSTPolicies)
}

// HandleKeygenMessage validates and applies one DKG envelope.
func (s *KeygenSession) HandleKeygenMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
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
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleKeygenConfirmation(env)
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen only accepts round 1 messages and round 2 confirmations"))
	}
	switch env.PayloadType {
	case payloadKeygenCommitments:
		p, err := unmarshalKeygenCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if existing, ok := s.commits[env.From]; ok {
			if equalByteSlices(existing, p.Commitments) && bytes.Equal(s.chainCodeComms[env.From], p.ChainCodeCommit) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting commitments"))
		}
		s.commits[env.From] = p.Commitments
		if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != sha256.Size {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("chain code commit must be 32 bytes, got %d", len(p.ChainCodeCommit)))
		}
		s.chainCodeComms[env.From] = append([]byte(nil), p.ChainCodeCommit...)
	case payloadKeygenShare:
		p, err := unmarshalKeygenSharePayload(env.Payload)
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
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting share"))
		}
		s.shares[env.From] = scalar
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return s.tryComplete()
}

// KeyShare returns the completed local key share when DKG has finished.
func (s *KeygenSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
		return nil, false
	}
	return cloneKeyShareValue(s.keyShare), true
}

const keygenConfirmationRound = 2

func (s *KeygenSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	if s.pending != nil {
		s.pending.Destroy()
	}
	s.pending = nil
}

func envelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType tss.PayloadType, payload []byte, confidential bool) tss.Envelope {
	e, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   config.SessionID,
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     payload,
	})
	if err != nil {
		panic(err)
	}
	if confidential {
		e.Security.Confidential = true
	}
	return e
}

const chainCodeCommitLabel = "frost-ed25519-chain-code-commit-v1"

// chainCodeCommitment produces a hash commitment for a party's HD chain code.
// The chain code is revealed in round 2 (keygen confirmation) and verified
// against this commitment to prevent last-sender bias.
func chainCodeCommitment(sessionID tss.SessionID, partyID tss.PartyID, chainCode []byte) []byte {
	if len(chainCode) == 0 {
		return nil
	}
	h := sha256.New()
	wire.WriteHashPart(h, []byte(chainCodeCommitLabel))
	wire.WriteHashPart(h, sessionID[:])
	wire.WriteHashPart(h, []byte{byte(partyID >> 24), byte(partyID >> 16), byte(partyID >> 8), byte(partyID)})
	wire.WriteHashPart(h, chainCode)
	return h.Sum(nil)
}

// verifyChainCodeCommit checks that a revealed chain code matches its round 1 commit.
func verifyChainCodeCommit(sessionID tss.SessionID, partyID tss.PartyID, chainCode, commit []byte) bool {
	if len(commit) == 0 {
		return len(chainCode) == 0
	}
	if len(commit) != sha256.Size || len(chainCode) != 32 {
		return false
	}
	expected := chainCodeCommitment(sessionID, partyID, chainCode)
	return bytes.Equal(expected, commit)
}
