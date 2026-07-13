package secp256k1

import (
	"errors"
	"fmt"
	"sync"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	keygenCommitmentsHashLabel = "cggmp21-secp256k1-keygen-commitments-v1"
	keygenTranscriptHashLabel  = "cggmp21-secp256k1-keygen-transcript-v1"
	cggmpChainCodeCommitLabel  = "cggmp21-secp256k1-chain-code-commit-v1"
)

type keygenState uint8

const (
	keygenCollectingRound1 keygenState = iota
	keygenAwaitingConfirmations
	keygenConfirmed
	keygenAborted
)

// KeygenSession tracks CGGMP21-style DKG state for one local party.
type KeygenSession struct {
	mu sync.Mutex

	cfg                  tss.ThresholdConfig                 // Local threshold runtime view fixed by the keygen plan.
	limits               Limits                              // Local fail-closed resource policy.
	securityParams       SecurityParams                      // Cryptographic profile for Paillier and proof material.
	planHash             []byte                              // Digest every keygen payload must echo.
	importPlan           *TrustedDealerImportPlan            // Optional public constraints for trusted-dealer import.
	local                *keygenLocalMaterial                // Locally generated material before pending-share commit.
	round1               *keygenRound1Inbox                  // Accepted round-1 material keyed by dealer.
	confirmations        *keygenConfirmationInbox            // Accepted confirmation material keyed by sender.
	pendingConfirmations map[tss.PartyID]*KeygenConfirmation // Confirmations awaiting sender round-1 commitments.
	sharesSent           bool                                // Encrypted share messages were emitted after all public material arrived.
	completed            bool                                // Terminal success flag after the key share is confirmed.
	aborted              bool                                // Terminal failure/destruction flag.
	state                keygenState                         // Phase marker for collection, confirmation, success, or abort.
	pending              *KeyShare                           // Completed but not yet confirmed key share.
	keyShare             *KeyShare                           // Confirmed key share retained by the session.
	guard                *tss.EnvelopeGuard                  // Transport replay, identity, and policy guard.
}

type keygenCommitmentsPayload struct {
	Commitments        [][]byte                  `json:"commitments" wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PaillierPublicKey  *pai.PublicKey            `json:"paillier_public_key" wire:"2,nested,max_bytes=paillier_public_key"`
	PaillierProof      *zkpai.ModulusProof       `json:"paillier_proof" wire:"3,nested,max_bytes=zk_proof"`
	ChainCodeCommit    []byte                    `json:"chain_code_commit,omitempty" wire:"4,bytes,len=32"`
	RingPedersenParams *zkpai.RingPedersenParams `json:"ring_pedersen_params" wire:"5,nested,max_bytes=ring_pedersen_params"`
	RingPedersenProof  *zkpai.RingPedersenProof  `json:"ring_pedersen_proof" wire:"6,nested,max_bytes=paillier_proof"`
	PlanHash           []byte                    `json:"plan_hash" wire:"7,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireType() string { return keygenCommitmentsPayloadWireType }

// WireVersion returns the wire format version for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireVersion() uint16 {
	return keygenCommitmentsPayloadWireVersion
}

type keygenSharePayload struct {
	Ciphertext  []byte             `wire:"1,bytes,max_bytes=paillier_ciphertext"`
	Proof       zkpai.LogStarProof `wire:"2,nested,max_bytes=zk_proof"`
	PlanHash    []byte             `wire:"3,bytes,len=32"`
	FactorProof zkpai.FactorProof  `wire:"4,nested,max_bytes=zk_proof"`
}

// WireType returns the canonical wire type identifier for keygenSharePayload.
func (keygenSharePayload) WireType() string { return keygenSharePayloadWireType }

// WireVersion returns the wire format version for keygenSharePayload.
func (keygenSharePayload) WireVersion() uint16 { return keygenSharePayloadWireVersion }

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *KeygenSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// Handle validates and applies one keygen envelope.
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
		err = bindInboundAuthenticationEvidence(err, env)
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
		switch base.PayloadType {
		case payloadKeygenCommitments:
			if base.Round != keygenStartRound {
				return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen commitments in wrong round"))
			}
			tx, err = s.buildAcceptCGGMPKeygenCommitmentsTx(base)
		case payloadKeygenShare:
			if base.Round != keygenShareRound {
				return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen encrypted share in wrong round"))
			}
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
