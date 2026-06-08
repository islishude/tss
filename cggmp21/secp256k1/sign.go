package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
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
// Fields are exported for binary encoding via [Presign.MarshalBinary]; JSON encoding
// is intentionally rejected by [Presign.MarshalJSON] to prevent accidental exposure
// of secret material.
type Presign struct {
	mu *sync.Mutex

	Version              uint16
	Party                tss.PartyID
	Threshold            int
	Signers              []tss.PartyID
	R                    []byte
	LittleR              []byte
	TranscriptHash       []byte
	Context              PresignContext
	ContextHash          []byte
	AdditiveShift        []byte
	PublicKey            []byte
	KeygenTranscriptHash []byte
	PartiesHash          []byte
	Consumed             bool

	kShare   *secret.Scalar
	chiShare *secret.Scalar
	delta    *secret.Scalar
}

// MarshalJSON rejects default JSON encoding of secret-bearing presign records.
func (p Presign) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 presign contains secret material; use MarshalBinary")
}

// MarshalBinary encodes the presign record using canonical TLV wire format.
func (p *Presign) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	kShare, err := secpSecretScalarBytes(p.kShare)
	if err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	chiShare, err := secpSecretScalarBytes(p.chiShare)
	if err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	delta, err := secpSecretScalarBytes(p.delta)
	if err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	return wire.Marshal(tss.Version, presignWireType, []wire.Field{
		{Tag: presignFieldParty, Value: wire.Uint32(uint32(p.Party))},
		{Tag: presignFieldThreshold, Value: wire.Uint32(uint32(p.Threshold))},
		{Tag: presignFieldSigners, Value: wire.EncodeUint32List(p.Signers)},
		{Tag: presignFieldR, Value: wire.NonNilBytes(p.R)},
		{Tag: presignFieldLittleR, Value: wire.NonNilBytes(p.LittleR)},
		{Tag: presignFieldKShare, Value: wire.NonNilBytes(kShare)},
		{Tag: presignFieldChiShare, Value: wire.NonNilBytes(chiShare)},
		{Tag: presignFieldDelta, Value: wire.NonNilBytes(delta)},
		{Tag: presignFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: presignFieldContext, Value: encodePresignContext(p.Context)},
		{Tag: presignFieldContextHash, Value: wire.NonNilBytes(p.ContextHash)},
		{Tag: presignFieldAdditiveShift, Value: wire.NonNilBytes(p.AdditiveShift)},
		{Tag: presignFieldConsumed, Value: wire.Bool(p.Consumed)},
		{Tag: presignFieldPublicKey, Value: wire.NonNilBytes(p.PublicKey)},
		{Tag: presignFieldKeygenTranscriptHash, Value: wire.NonNilBytes(p.KeygenTranscriptHash)},
		{Tag: presignFieldPartiesHash, Value: wire.NonNilBytes(p.PartiesHash)},
	})
}

// Validate checks local presign structure and scalar/point encodings.
func (p *Presign) Validate() error {
	if p == nil {
		return errors.New("nil presign")
	}
	if p.Version != tss.Version {
		return fmt.Errorf("unexpected presign version %d", p.Version)
	}
	if p.Threshold <= 0 || p.Threshold > len(p.Signers) {
		return errors.New("invalid presign threshold")
	}
	if err := wire.ValidateStrictSortedIDs(p.Signers); err != nil {
		return err
	}
	if !tss.ContainsParty(p.Signers, p.Party) {
		return errors.New("presign party is not in signer set")
	}
	if _, err := secp.PointFromBytes(p.R); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	if _, err := secp.ScalarFromBytes(p.LittleR); err != nil {
		return fmt.Errorf("invalid little r: %w", err)
	}
	if _, err := secpScalarFromSecret(p.kShare); err != nil {
		return fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secpScalarFromSecret(p.chiShare); err != nil {
		return fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secpScalarFromSecret(p.delta); err != nil {
		return fmt.Errorf("invalid delta: %w", err)
	}
	if len(p.TranscriptHash) != 32 {
		return errors.New("invalid presign transcript hash")
	}
	if err := validatePresignContext(p.Context); err != nil {
		return err
	}
	if len(p.ContextHash) != 32 {
		return errors.New("invalid presign context hash")
	}
	if len(p.AdditiveShift) > 0 {
		if _, err := secp.ScalarFromBytes(p.AdditiveShift); err != nil {
			return fmt.Errorf("invalid additive shift: %w", err)
		}
	}
	if _, err := secp.PointFromBytes(p.PublicKey); err != nil {
		return fmt.Errorf("invalid presign public key binding: %w", err)
	}
	if len(p.KeygenTranscriptHash) != sha256.Size {
		return errors.New("invalid presign keygen transcript hash binding")
	}
	if len(p.PartiesHash) != sha256.Size {
		return errors.New("invalid presign party-set hash binding")
	}
	if !bytes.Equal(presignContextHash(p.Context), p.ContextHash) {
		return errors.New("presign context hash mismatch")
	}
	return nil
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
	guard         *tss.EnvelopeGuard

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
	guard     *tss.EnvelopeGuard
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

// Guard returns the session's envelope guard for use by transport adapters.
func (s *PresignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// SetGuard attaches an envelope guard to the session. When set, all inbound
// envelopes are validated against protocol policies, transport authentication,
// confidentiality requirements, broadcast consistency, and replay detection.
func (s *PresignSession) SetGuard(g *tss.EnvelopeGuard) {
	if s != nil {
		s.guard = g
	}
}

// NewGuard creates an EnvelopeGuard configured for this presign session.
// cache may be nil to use an in-memory cache suitable for testing.
func (s *PresignSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil presign session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	return tss.NewEnvelopeGuard(s.key.Party, tss.PartySet(s.key.Parties), protocol, s.sessionID, CGGMP21Policies, cache)
}

// validateInbound runs envelope validation through the guard when set, or
// falls back to basic structural checks for sessions without a guard (tests).
// Production deployments MUST attach a guard via SetGuard before processing
// authenticated transport messages.
func (s *PresignSession) validateInbound(env tss.Envelope) error {
	if s.guard != nil {
		return s.guard.Validate(env)
	}
	// Guard is required when the transport authenticates the sender.
	if env.Security.Authenticated {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From,
			errors.New("envelope guard is required for authenticated transport; call SetGuard before processing messages"))
	}
	if err := tss.ValidateEnvelope(env, protocol, s.sessionID, s.key.Parties); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := tss.ValidateEnvelopePolicy(env, s.key.Party, CGGMP21Policies); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	return nil
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
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}

	switch env.PayloadType {
	case payloadPresignRound1:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round1 payload in wrong round"))
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
