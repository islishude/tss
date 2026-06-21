package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	keygenCommitmentsHashLabel = "cggmp21-secp256k1-keygen-commitments-v1"
	keygenTranscriptHashLabel  = "cggmp21-secp256k1-keygen-transcript-v1"

	keygenStartRound        = 1
	keygenConfirmationRound = 2
)

type keygenState uint8

const (
	keygenCollecting keygenState = iota
	keygenLocalComplete
	keygenConfirming
	keygenConfirmed
	keygenAborted
)

// keygenPartyData holds all per-party DKG state for a single participant.
// All fields other than confirmation are populated during round 1;
// confirmation is set during round 2 after the chain code is revealed.
type keygenPartyData struct {
	commitments     [][]byte
	share           *secret.Scalar
	chainCode       []byte
	chainCodeCommit []byte
	paillierPub     paillierPublicMaterial
	ringPedersen    ringPedersenPublicMaterial
	confirmation    *KeygenConfirmation
}

// KeygenSession tracks CGGMP21-style DKG state for one local party.
type KeygenSession struct {
	mu sync.Mutex

	cfg            tss.ThresholdConfig              // Local threshold runtime view fixed by the keygen plan.
	limits         Limits                           // Local fail-closed resource policy.
	securityParams SecurityParams                   // Cryptographic profile for Paillier and proof material.
	planHash       []byte                           // Digest every keygen payload must echo.
	partyData      map[tss.PartyID]*keygenPartyData // Per-party DKG state keyed by sender.
	paillier       *pai.PrivateKey                  // Local Paillier private key generated for the key share.
	completed      bool                             // Terminal success flag after the key share is confirmed.
	aborted        bool                             // Terminal failure/destruction flag.
	state          keygenState                      // Phase marker for collect, local-complete, and confirmation states.
	pending        *KeyShare                        // Completed but not yet confirmed key share.
	keyShare       *KeyShare                        // Confirmed key share retained by the session.
	guard          *tss.EnvelopeGuard               // Transport replay, identity, and policy guard.
}

// GetChainCodeCommitByPartyId gets a copy of chainCodeCommit by partyId
// It returns nil if the id doesn't exist
func (s *KeygenSession) GetChainCodeCommitByPartyId(id tss.PartyID) []byte {
	data, err := s.partyEntry(id)
	if err == nil {
		return bytes.Clone(data.chainCodeCommit)
	}
	return nil
}

type keygenCommitmentsPayload struct {
	Commitments        [][]byte                 `json:"commitments" wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PaillierPublicKey  pai.PublicKey            `json:"paillier_public_key" wire:"2,nested,max_bytes=paillier_public_key"`
	PaillierProof      zkpai.ModulusProof       `json:"paillier_proof" wire:"3,nested,max_bytes=zk_proof"`
	ChainCodeCommit    []byte                   `json:"chain_code_commit,omitempty" wire:"4,bytes,len=32"`
	RingPedersenParams zkpai.RingPedersenParams `json:"ring_pedersen_params" wire:"5,nested,max_bytes=ring_pedersen_params"`
	RingPedersenProof  zkpai.RingPedersenProof  `json:"ring_pedersen_proof" wire:"6,nested,max_bytes=paillier_proof"`
	PlanHash           []byte                   `json:"plan_hash" wire:"7,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireType() string { return keygenCommitmentsPayloadWireType }

// WireVersion returns the wire format version for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireVersion() uint16 {
	return keygenCommitmentsPayloadWireVersion
}

type keygenSharePayload struct {
	Share    *secret.Scalar `wire:"1,custom,len=32"`
	PlanHash []byte         `wire:"2,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for keygenSharePayload.
func (keygenSharePayload) WireType() string { return keygenSharePayloadWireType }

// WireVersion returns the wire format version for keygenSharePayload.
func (keygenSharePayload) WireVersion() uint16 { return keygenSharePayloadWireVersion }

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *KeygenSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// partyEntry returns the per-party data for id, or an error when id is not in the session.
func (s *KeygenSession) partyEntry(id tss.PartyID) (*keygenPartyData, error) {
	pd, ok := s.partyData[id]
	if !ok {
		return nil, fmt.Errorf("party %d is not a keygen participant", id)
	}
	return pd, nil
}

// HandleKeygenMessage validates and applies one keygen envelope.
func (s *KeygenSession) HandleKeygenMessage(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
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
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}

	var tx sessionTransition[KeygenSession]
	if base.PayloadType == payloadKeygenConfirmation {
		if base.Round != keygenConfirmationRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen confirmation in wrong round"))
		}
		tx, err = s.buildAcceptCGGMPKeygenConfirmationTx(base)
	} else {
		if base.Round != keygenStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen only accepts round 1 messages"))
		}
		switch base.PayloadType {
		case payloadKeygenCommitments:
			tx, err = s.buildAcceptCGGMPKeygenCommitmentsTx(base)
		case payloadKeygenShare:
			tx, err = s.buildAcceptCGGMPKeygenShareTx(base)
		default:
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
		}
	}
	if err != nil {
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
