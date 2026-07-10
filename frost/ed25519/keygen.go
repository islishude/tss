package ed25519

import (
	"errors"
	"sync"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type keygenState uint8

const (
	keygenCollectingRound1 keygenState = iota
	keygenAwaitingConfirmations
	keygenConfirmed
	keygenAborted
)

// KeygenSession tracks dealerless FROST DKG state for one local party.
type KeygenSession struct {
	mu                   sync.Mutex
	cfg                  tss.ThresholdConfig
	limits               Limits
	planHash             []byte
	guard                *tss.EnvelopeGuard
	local                *frostKeygenLocalMaterial
	round1               *frostKeygenRound1Inbox
	confirmations        *frostKeygenConfirmationInbox
	pendingConfirmations map[tss.PartyID]*KeygenConfirmation
	pending              *frostPendingKeyShare
	keyShare             *KeyShare
	state                keygenState
	completed            bool
	aborted              bool
}

type keygenCommitmentsPayload struct {
	Commitments     keygenCommitments `json:"commitments" wire:"1,custom,max_items=threshold"`
	ChainCodeCommit []byte            `json:"chain_code_commit,omitempty" wire:"2,bytes"`
	PlanHash        []byte            `json:"plan_hash" wire:"3,bytes,len=32"`
}

const keygenCommitmentsPayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireType() string { return keygenCommitmentsPayloadWireType }

// WireVersion returns the wire format version for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireVersion() uint16 {
	return keygenCommitmentsPayloadWireVersion
}

type keygenSharePayload struct {
	Share    *secret.Scalar `json:"share" wire:"1,custom,len=32"`
	PlanHash []byte         `json:"plan_hash" wire:"2,bytes,len=32"`
}

const keygenSharePayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for keygenSharePayload.
func (keygenSharePayload) WireType() string { return keygenSharePayloadWireType }

// WireVersion returns the wire format version for keygenSharePayload.
func (keygenSharePayload) WireVersion() uint16 { return keygenSharePayloadWireVersion }

// MarshalJSON rejects default JSON encoding of secret DKG shares.
func (keygenSharePayload) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 keygen share payload must use wire encoding (MarshalBinary)")
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *KeygenSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolFROSTEd25519, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// Handle validates and applies one DKG envelope.
func (s *KeygenSession) Handle(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if s == nil {
		return nil, errors.New("nil keygen session")
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
	tx, err := s.buildKeygenTransition(env)
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

func (s *KeygenSession) abort() {
	if s == nil {
		return
	}
	if s.aborted {
		return
	}
	if s.local != nil {
		s.local.Destroy()
		s.local = nil
	}
	if s.round1 != nil {
		s.round1.DestroySecrets()
	}
	if s.confirmations != nil {
		s.confirmations.ClearReveals()
	}
	for id, confirmation := range s.pendingConfirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(s.pendingConfirmations, id)
	}
	s.aborted = true
	if s.pending != nil {
		s.pending.Destroy()
	}
	s.pending = nil
	if s.keyShare != nil && !s.completed {
		s.keyShare.Destroy()
		s.keyShare = nil
	}
	s.completed = false
	s.state = keygenAborted
}

func newEnvelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType tss.PayloadType, payload []byte) (tss.Envelope, error) {
	return tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   config.SessionID,
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     payload,
	})
}
