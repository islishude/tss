package secp256k1

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

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

	// Limits overrides the default protocol limits. When nil, DefaultLimits is used.
	Limits *Limits
}

// KeygenSession tracks CGGMP21-style DKG state for one local party.
type KeygenSession struct {
	mu sync.Mutex

	cfg            tss.ThresholdConfig
	log            tss.Logger
	limits         Limits
	planHash       []byte
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
	Commitments        [][]byte `json:"commitments" wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PaillierPublicKey  []byte   `json:"paillier_public_key" wire:"2,bytes,max_bytes=paillier_public_key"`
	PaillierProof      []byte   `json:"paillier_proof" wire:"3,bytes,max_bytes=zk_proof"`
	ChainCodeCommit    []byte   `json:"chain_code_commit,omitempty" wire:"4,bytes"`
	RingPedersenParams []byte   `json:"ring_pedersen_params" wire:"5,bytes,max_bytes=ring_pedersen_params"`
	RingPedersenProof  []byte   `json:"ring_pedersen_proof" wire:"6,bytes,max_bytes=paillier_proof"`
	PlanHash           []byte   `json:"plan_hash" wire:"7,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireType() string { return keygenCommitmentsPayloadWireType }

// WireVersion returns the wire format version for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireVersion() uint16 { return tss.Version }

type keygenSharePayload struct {
	Share    *big.Int `wire:"1,bigpos,max_bytes=scalar"`
	PlanHash []byte   `wire:"2,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for keygenSharePayload.
func (keygenSharePayload) WireType() string { return keygenSharePayloadWireType }

// WireVersion returns the wire format version for keygenSharePayload.
func (keygenSharePayload) WireVersion() uint16 { return tss.Version }

// Guard returns the session's envelope guard for use by transport adapters.
func (s *KeygenSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *KeygenSession) validateInbound(env tss.Envelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// HandleKeygenMessage validates and applies one keygen envelope.
// It dispatches to per-round/per-phase handlers that each follow the template:
// parse → policy validate → cryptographic verify → mutate state → emit.
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
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
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
