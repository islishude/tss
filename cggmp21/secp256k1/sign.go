package secp256k1

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
)

const (
	presignTranscriptHashLabel = "cggmp21-secp256k1-presign-transcript-v1"
	presignContextHashLabel    = "cggmp21-secp256k1-presign-context-v1"
	presignRound1EchoLabel     = "cggmp21-secp256k1-presign-round1-echo-v1"
	presignRound1PublicLabel   = "cggmp21-secp256k1-presign-round1-public-v1"
	signMessageDigestLabel     = "cggmp21-secp256k1-sign-message-v1"
	mtaResponseEvidenceLabel   = "cggmp21-secp256k1-mta-response-evidence-v1"
	aggregateSignEvidenceLabel = "cggmp21-secp256k1-aggregate-sign-evidence-v1"
)

// PresignContext binds a presignature to the key, chain, derivation path,
// policy, and message domain where it may be consumed. An empty DerivationPath
// is the canonical master-key path; non-empty paths are non-hardened BIP32.
type PresignContext struct {
	KeyID          string   `json:"key_id"`
	ChainID        string   `json:"chain_id"`
	DerivationPath []uint32 `json:"derivation_path"`
	PolicyDomain   string   `json:"policy_domain"`
	MessageDomain  string   `json:"message_domain"`
}

// PresignStore is an optional durable claim interface. When provided to StartSign,
// the library calls MarkConsumed with the presign's unique transcript hash before
// it constructs any outbound signing partial. If the store write fails, StartSign
// reverts the in-memory consumed flag and returns an error — the presign is not
// consumed and can be retried.
//
// A typical implementation persists the presign record with Consumed=true in an
// atomic compare-and-swap or conditional-insert operation keyed by the transcript
// hash. The transcript hash uniquely identifies one presign instance and can be
// used as an idempotency key.
type PresignStore interface {
	MarkConsumed(presignTranscriptHash []byte) error
}

// SignRequest is the context-bound online signing request for a persisted
// presignature. Message is hashed with the presign context before ECDSA.
type SignRequest struct {
	Context      PresignContext `json:"context"`
	Message      []byte         `json:"message"`
	LowS         bool           `json:"low_s"`
	PresignStore PresignStore   `json:"-"` // optional durable claim hook
}

// Presign contains one local offline signing record and must be consumed once.
type Presign struct {
	mu *sync.Mutex

	Version              uint16         `json:"version"`
	Party                tss.PartyID    `json:"party"`
	Threshold            int            `json:"threshold"`
	Signers              []tss.PartyID  `json:"signers"`
	R                    []byte         `json:"r"`
	LittleR              []byte         `json:"little_r"`
	TranscriptHash       []byte         `json:"transcript_hash"`
	Context              PresignContext `json:"context"`
	ContextHash          []byte         `json:"context_hash"`
	AdditiveShift        []byte         `json:"additive_shift"`
	PublicKey            []byte         `json:"public_key"`
	KeygenTranscriptHash []byte         `json:"keygen_transcript_hash"`
	PartiesHash          []byte         `json:"parties_hash"`
	Consumed             bool           `json:"consumed"`

	kShare   *secret.Scalar
	chiShare *secret.Scalar
	delta    *secret.Scalar
}

// MarshalJSON rejects default JSON encoding of secret-bearing presign records.
func (p Presign) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 presign contains secret material; use MarshalBinary")
}

// Destroy marks the presign consumed and clears its local secret shares.
func (p *Presign) Destroy() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.Consumed = true
	p.mu.Unlock()
	p.kShare.Destroy()
	p.chiShare.Destroy()
	p.delta.Destroy()
	clear(p.AdditiveShift)
}

// PresignSession tracks the CGGMP21-style offline presign exchange.
type PresignSession struct {
	key           *KeyShare
	sessionID     tss.SessionID
	config        tss.ThresholdConfig
	log           tss.Logger
	signers       []tss.PartyID
	context       PresignContext
	contextHash   []byte
	additiveShift []byte
	paillier      *pai.PrivateKey

	kShare    *secret.Scalar
	gamma     *secret.Scalar
	xBar      *secret.Scalar
	gammaComm []byte
	xBarComm  []byte

	round1               map[tss.PartyID]presignRound1Payload
	round1Proofs         map[tss.PartyID]presignRound1ProofPayload
	round1ProofEnvelopes map[tss.PartyID]tss.Envelope
	round1Verified       map[tss.PartyID]bool
	round2               map[tss.PartyID]presignRound2Payload
	deltas               map[tss.PartyID]*big.Int
	startOpening         *mta.StartOpening

	alphaDelta map[tss.PartyID]*big.Int
	betaDelta  map[tss.PartyID]*big.Int
	alphaSigma map[tss.PartyID]*big.Int
	betaSigma  map[tss.PartyID]*big.Int

	round2Sent bool
	round3Sent bool
	completed  bool
	aborted    bool
	presign    *Presign
}

// SignSession tracks the online threshold ECDSA signing exchange.
type SignSession struct {
	key       *KeyShare
	presign   *Presign
	sessionID tss.SessionID
	log       tss.Logger
	digest    []byte
	lowS      bool
	publicKey []byte
	partials  map[tss.PartyID]*big.Int
	completed bool
	aborted   bool
	signature *Signature
}

type presignRound1Payload struct {
	Gamma             []byte `json:"gamma"`
	EncK              []byte `json:"enc_k"`
	PaillierPublicKey []byte `json:"paillier_public_key"`
}

type presignRound1ProofPayload struct {
	PublicRound1Hash []byte `json:"public_round1_hash"`
	EncKProof        []byte `json:"enc_k_proof"`
}

type presignRound2Payload struct {
	Delta      mta.ResponseMessage `json:"delta"`
	Sigma      mta.ResponseMessage `json:"sigma"`
	Round1Echo []byte              `json:"round1_echo"`
}

type presignRound3Payload struct {
	Delta []byte `json:"delta"`
}

type signPartialPayload struct {
	S                 []byte `json:"s"`
	PresignTranscript []byte `json:"presign_transcript"`
	PresignContext    []byte `json:"presign_context"`
}

// HandlePresignMessage validates and applies one presign envelope.
// It dispatches to per-round handlers that each follow the template:
// parse → policy validate → cryptographic verify → mutate state → emit.
func (s *PresignSession) HandlePresignMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil presign session")
	}
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.aborted = true
		}
	}()
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}

	switch env.PayloadType {
	case payloadPresignRound1:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round1 payload in wrong round"))
		}
		if env.To != 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("presign round1 public payload must be broadcast"))
		}
		if env.ConfidentialRequired {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("presign round1 public payload must not require confidential transport"))
		}
		if _, ok := s.round1[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round1"))
		}
		return s.handlePresignRound1(env)

	case payloadPresignRound1Proof:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round1 proof payload in wrong round"))
		}
		if env.From == s.key.Party {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("self presign round1 proof is not expected"))
		}
		if err := requireDirectConfidential(env, s.key.Party, payloadPresignRound1Proof); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, ok := s.round1Proofs[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round1 proof"))
		}
		return s.handlePresignRound1Proof(env)

	case payloadPresignRound2:
		if env.Round != 2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round2 payload in wrong round"))
		}
		if _, ok := s.round2[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round2"))
		}
		return s.handlePresignRound2(env)

	case payloadPresignRound3:
		if env.Round != 3 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round3 payload in wrong round"))
		}
		if _, ok := s.deltas[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate delta share"))
		}
		return s.handlePresignRound3(env)

	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
}

// Presign returns a deep copy of the completed local presign record.
func (s *PresignSession) Presign() (*Presign, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.presign.Clone(), true
}
