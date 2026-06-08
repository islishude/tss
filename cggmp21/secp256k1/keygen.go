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
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.cfg.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.To != 0 && env.To != s.cfg.Self {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}

	// Round 2 (confirmation) dispatch.
	if env.PayloadType == payloadKeygenConfirmation {
		if env.Round != keygenConfirmationRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen confirmation in wrong round"))
		}
		if env.To != 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("keygen confirmation must be broadcast"))
		}
		if env.ConfidentialRequired {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("keygen confirmation must not require confidential transport"))
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
		if err := requireDirectConfidential(env, s.cfg.Self, payloadKeygenShare); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
		}
		return s.handleKeygenShare(env)

	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
}
