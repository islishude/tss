package secp256k1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
)

const (
	keygenCommitmentsHashLabel = "cggmp21-secp256k1-keygen-commitments-v1"
	keygenTranscriptHashLabel  = "cggmp21-secp256k1-keygen-transcript-v1"
	keygenConfirmationRound    = 2
)

type keygenState uint8

const (
	keygenCollecting keygenState = iota
	keygenLocalComplete
	keygenConfirming
	keygenConfirmed
	keygenAborted
)

// KeygenOptions controls non-default CGGMP21 keygen parameters.
type KeygenOptions struct {
	PaillierBits int
	EnableHD     bool
}

// KeygenSession tracks CGGMP21-style DKG state for one local party.
type KeygenSession struct {
	cfg            tss.ThresholdConfig
	log            tss.Logger
	commits        map[tss.PartyID][][]byte
	shares         map[tss.PartyID]*big.Int
	chainCodes     map[tss.PartyID][]byte
	chainCodeComms map[tss.PartyID][]byte
	enableHD       bool
	paillier       *pai.PrivateKey
	paillierPubs   map[tss.PartyID]PaillierPublicShare
	ringPedersen   map[tss.PartyID]RingPedersenPublicShare
	completed      bool
	aborted        bool
	state          keygenState
	pending        *pendingKeyShare
	confirmations  map[tss.PartyID][]byte
	keyShare       *KeyShare
	guard          *tss.EnvelopeGuard
}

type pendingKeyShare struct {
	share *KeyShare
}

type keygenCommitmentsPayload struct {
	Commitments        [][]byte `json:"commitments"`
	PaillierPublicKey  []byte   `json:"paillier_public_key"`
	PaillierProof      []byte   `json:"paillier_proof"`
	ChainCodeCommit    []byte   `json:"chain_code_commit,omitempty"`
	RingPedersenParams []byte   `json:"ring_pedersen_params"`
	RingPedersenProof  []byte   `json:"ring_pedersen_proof"`
}

type keygenSharePayload struct {
	Share []byte `json:"share"`
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

// NewGuard creates an EnvelopeGuard configured for this session from the
// production CGGMP21 policy set. cache may be nil to use an in-memory cache
// suitable for testing; production deployments must supply a durable ReplayCache.
func (s *KeygenSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	return tss.NewEnvelopeGuard(s.cfg.Self, tss.PartySet(s.cfg.Parties), protocol, s.cfg.SessionID, CGGMP21Policies, cache)
}

// validateInbound runs envelope validation through the guard when set, or
// falls back to basic structural checks for sessions without a guard (tests).
// Production deployments MUST attach a guard via SetGuard before processing
// authenticated transport messages.
func (s *KeygenSession) validateInbound(env tss.Envelope) error {
	if s.guard != nil {
		return s.guard.Validate(env)
	}
	// Guard is required when the transport authenticates the sender.
	// Tests that bypass transport simulation leave Authenticated=false.
	if env.Security.Authenticated {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From,
			errors.New("envelope guard is required for authenticated transport; call SetGuard before processing messages"))
	}
	if err := tss.ValidateEnvelope(env, protocol, s.cfg.SessionID, s.cfg.Parties); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := tss.ValidateEnvelopePolicy(env, s.cfg.Self, CGGMP21Policies); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	return nil
}

// HandleKeygenMessage validates and applies one keygen envelope.
// It dispatches to per-round/per-phase handlers that each follow the template:
// parse → policy validate → cryptographic verify → mutate state → emit.
func (s *KeygenSession) HandleKeygenMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
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

	// Round 2 (confirmation) dispatch.
	if env.PayloadType == payloadKeygenConfirmation {
		if env.Round != keygenConfirmationRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen confirmation in wrong round"))
		}
		return s.handleKeygenConfirmation(env)
	}

	// Round 1 dispatch.
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadKeygenCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate commitments"))
		}
		return s.handleKeygenCommitments(env)

	case payloadKeygenShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
		}
		return s.handleKeygenShare(env)

	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
}
