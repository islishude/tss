package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/zk/signprep"
)

const (
	presignTranscriptHashLabel = "cggmp21-secp256k1-presign-transcript-v1"
	presignContextHashLabel    = "cggmp21-secp256k1-presign-context-v1"
	presignRound1EchoLabel     = "cggmp21-secp256k1-presign-round1-echo-v1"
	presignRound1PublicLabel   = "cggmp21-secp256k1-presign-round1-public-v1"
	signMessageDigestLabel     = "cggmp21-secp256k1-sign-message-v1"
	mtaResponseEvidenceLabel   = "cggmp21-secp256k1-mta-response-evidence-v1"
)

// PresignContext binds a presignature to the key, chain, derivation path,
// policy, and message domain where it may be consumed. An empty DerivationPath
// is the canonical master-key path; non-empty paths are non-hardened BIP32.
type PresignContext struct {
	KeyID          string   `json:"key_id" wire:"1,string"`
	ChainID        string   `json:"chain_id" wire:"2,string"`
	DerivationPath []uint32 `json:"derivation_path" wire:"3,u32list"`
	PolicyDomain   string   `json:"policy_domain" wire:"4,string"`
	MessageDomain  string   `json:"message_domain" wire:"5,string"`
}

// WireType returns the canonical wire type identifier for PresignContext.
func (PresignContext) WireType() string { return presignContextWireType }

// WireVersion returns the wire format version for PresignContext.
func (PresignContext) WireVersion() uint16 { return tss.Version }

// ErrPresignAlreadyConsumed reports that a durable presign claim already exists.
var ErrPresignAlreadyConsumed = errors.New("presign already consumed")

// PresignStore is the durable one-use boundary for online signing. StartSign
// calls ClaimPresign with the presign's content-derived identifier ([Presign.ID])
// after the local in-process claim succeeds and before it constructs any
// outbound signing partial.
//
// ClaimPresign must be atomic for each presign identifier. It returns nil only
// when this caller won the durable claim. It must return
// [ErrPresignAlreadyConsumed] when the identifier was already claimed, so callers
// can fail closed with [tss.ErrCodeConsumed]. For temporary storage failures,
// return any other error; StartSign rolls back the local claim because no
// outbound signing partial has been constructed yet.
type PresignStore interface {
	ClaimPresign(presignID []byte) error
}

// SignRequest is the context-bound online signing request for a persisted
// presignature. Message is hashed with the presign context before ECDSA.
type SignRequest struct {
	Context      PresignContext `json:"context"`
	Message      []byte         `json:"message"`
	LowS         bool           `json:"low_s"`
	PresignStore PresignStore   `json:"-"` // required durable claim hook
}

// Presign contains one local offline signing record and must be consumed once.
// MarshalBinary maps it to the canonical private wire record, including a
// consumed snapshot from the internal claim. JSON encoding is intentionally
// rejected by [Presign.MarshalJSON] to prevent accidental exposure of secret
// material.
type Presign struct {
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
	VerifyShares         []SignVerifyShare

	kShare   *secret.Scalar
	chiShare *secret.Scalar
	delta    *secret.Scalar

	consumed *atomic.Bool
}

// MarshalJSON rejects default JSON encoding of secret-bearing presign records.
func (p Presign) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 presign contains secret material; use MarshalBinary")
}

// MarshalBinary encodes the presign record using the object-level wire codec.
func (p *Presign) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	consumed := IsPresignConsumed(p)
	return wire.Marshal(presignWire{
		Party:                p.Party,
		Threshold:            p.Threshold,
		Signers:              p.Signers,
		R:                    p.R,
		LittleR:              p.LittleR,
		KShare:               p.kShare,
		ChiShare:             p.chiShare,
		Delta:                p.delta,
		TranscriptHash:       p.TranscriptHash,
		Context:              p.Context,
		ContextHash:          p.ContextHash,
		AdditiveShift:        p.AdditiveShift,
		Consumed:             consumed,
		PublicKey:            p.PublicKey,
		KeygenTranscriptHash: p.KeygenTranscriptHash,
		PartiesHash:          p.PartiesHash,
		VerifyShares:         encodeSignVerifyShares(p.VerifyShares),
	}, wire.WithFieldLimitsForMarshal(DefaultLimits().fieldLimits()))
}

const presignIDLabel = "cggmp21-secp256k1-presign-id-v1"

// ID returns a content-derived presign identifier suitable for use as an
// idempotency key in a durable [PresignStore]. The returned hash is computed
// from all persisted presign fields, including secret material, and does not
// depend on [Presign.TranscriptHash] or the local consumed claim. Tampering with any
// persisted field changes the identifier, so a storage layer cannot alter the
// idempotency key independently of the presign contents.
func (p *Presign) ID() []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignIDLabel))
	wire.WriteHashPart(h, p.ContextHash)
	wire.WriteHashPart(h, p.AdditiveShift)
	wire.WriteHashPart(h, p.PublicKey)
	wire.WriteHashPart(h, p.KeygenTranscriptHash)
	wire.WriteHashPart(h, p.PartiesHash)
	for _, id := range p.Signers {
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
	}
	for _, vs := range p.VerifyShares {
		wire.WriteHashPart(h, vs.KPoint)
		wire.WriteHashPart(h, vs.ChiPoint)
		proofHash := sha256.Sum256(vs.Proof)
		wire.WriteHashPart(h, proofHash[:])
	}
	wire.WriteHashPart(h, p.R)
	wire.WriteHashPart(h, p.LittleR)
	wire.WriteHashPart(h, p.kShare.FixedBytes())
	wire.WriteHashPart(h, p.chiShare.FixedBytes())
	wire.WriteHashPart(h, p.delta.FixedBytes())
	return h.Sum(nil)
}

// Validate checks local presign structure and scalar/point encodings.
func (p *Presign) Validate() error {
	if p == nil {
		return errors.New("nil presign")
	}
	if p.consumed == nil {
		return errors.New("presign claim state unavailable")
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
	if err := validateSignVerifyShares(p.Signers, p.VerifyShares); err != nil {
		return fmt.Errorf("invalid presign verify shares: %w", err)
	}
	return nil
}

// VerifySignMaterial performs a structural integrity check on all SignVerifyShare
// entries in the presign record. Full cryptographic verification of each signprep
// proof happens during presign round 3 (with session ID bound). At StartSign time
// the presign transcript hash already binds every proof hash, so tampering would
// be caught by transcript mismatch. This method catches malformed proofs or
// invalid point encodings that may have resulted from storage corruption.
func (p *Presign) VerifySignMaterial() error {
	if p == nil {
		return errors.New("nil presign")
	}
	if err := validateSignVerifyShares(p.Signers, p.VerifyShares); err != nil {
		return err
	}
	for _, share := range p.VerifyShares {
		if _, err := signprep.UnmarshalProof(share.Proof); err != nil {
			return fmt.Errorf("verify share party %d: invalid proof: %w", share.Party, err)
		}
	}
	return nil
}

// Destroy marks the presign consumed and clears its local secret shares.
func (p *Presign) Destroy() {
	if p == nil {
		return
	}
	if p.consumed != nil {
		p.consumed.Store(true)
	}
	p.kShare.Destroy()
	p.chiShare.Destroy()
	p.delta.Destroy()
	clear(p.AdditiveShift)
}

// PresignSession tracks the CGGMP21-style offline presign exchange.
type PresignSession struct {
	mu sync.Mutex

	key           *KeyShare
	sessionID     tss.SessionID
	config        tss.ThresholdConfig
	log           tss.Logger
	limits        Limits
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
	verifyShares         map[tss.PartyID]SignVerifyShare
	startOpening         *mta.StartOpening

	alphaDelta map[tss.PartyID]*big.Int
	betaDelta  map[tss.PartyID]*big.Int
	alphaSigma map[tss.PartyID]*big.Int
	betaSigma  map[tss.PartyID]*big.Int

	round2Sent      bool
	round3Sent      bool
	completed       bool
	aborted         bool
	presign         *Presign
	presignReturned bool
}

// abort marks the presign session aborted and clears all secret-bearing
// accumulated state (nonce scalars, Paillier key, MtA shares, delta shares,
// round payloads, start opening, and any completed presign record).
func (s *PresignSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.kShare.Destroy()
	s.gamma.Destroy()
	s.xBar.Destroy()
	s.kShare = nil
	s.gamma = nil
	s.xBar = nil
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	clearBigIntMap(s.deltas)
	clearBigIntMap(s.alphaDelta)
	clearBigIntMap(s.betaDelta)
	clearBigIntMap(s.alphaSigma)
	clearBigIntMap(s.betaSigma)
	clearPresignRound1Map(s.round1)
	clearPresignRound2Map(s.round2)
	if s.startOpening != nil {
		s.startOpening.Destroy()
		s.startOpening = nil
	}
	if s.presign != nil {
		s.presign.Destroy()
		s.presign = nil
	}
}

// SignSession tracks the online threshold ECDSA signing exchange.
type SignSession struct {
	mu sync.Mutex

	key       *KeyShare
	presign   *Presign
	sessionID tss.SessionID
	guard     *tss.EnvelopeGuard
	log       tss.Logger
	limits    Limits
	digest    []byte
	lowS      bool
	publicKey []byte
	partials  map[tss.PartyID]*big.Int
	completed bool
	aborted   bool
	signature *Signature
}

// abort marks the signing session aborted and clears secret-bearing
// accumulated state (signing partials and message digest).
func (s *SignSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	clearBigIntMap(s.partials)
	clear(s.digest)
	s.digest = nil
}

type presignRound1Payload struct {
	Gamma             []byte `json:"gamma" wire:"1,bytes,max_bytes=point"`
	EncK              []byte `json:"enc_k" wire:"2,bytes,max_bytes=paillier_ciphertext"`
	PaillierPublicKey []byte `json:"paillier_public_key" wire:"3,bytes,max_bytes=paillier_public_key"`
}

// WireType returns the canonical wire type identifier for presignRound1Payload.
func (presignRound1Payload) WireType() string { return presignRound1PayloadWireType }

// WireVersion returns the wire format version for presignRound1Payload.
func (presignRound1Payload) WireVersion() uint16 { return tss.Version }

type presignRound1ProofPayload struct {
	PublicRound1Hash []byte `json:"public_round1_hash" wire:"1,bytes,len=32"`
	EncKProof        []byte `json:"enc_k_proof" wire:"2,bytes,max_bytes=zk_proof"`
}

// WireType returns the canonical wire type identifier for presignRound1ProofPayload.
func (presignRound1ProofPayload) WireType() string { return presignRound1ProofPayloadWireType }

// WireVersion returns the wire format version for presignRound1ProofPayload.
func (presignRound1ProofPayload) WireVersion() uint16 { return tss.Version }

type presignRound2Payload struct {
	Delta      mta.ResponseMessage `json:"delta" wire:"1,nested"`
	Sigma      mta.ResponseMessage `json:"sigma" wire:"2,nested"`
	Round1Echo []byte              `json:"round1_echo" wire:"3,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound2Payload.
func (presignRound2Payload) WireType() string { return presignRound2PayloadWireType }

// WireVersion returns the wire format version for presignRound2Payload.
func (presignRound2Payload) WireVersion() uint16 { return tss.Version }

type presignRound3Payload struct {
	Delta    *big.Int `json:"-" wire:"1,bigpos,max_bytes=scalar"`
	KPoint   []byte   `json:"k_point" wire:"2,bytes,max_bytes=point"`
	ChiPoint []byte   `json:"chi_point" wire:"3,bytes,max_bytes=point"`
	Proof    []byte   `json:"proof" wire:"4,bytes,max_bytes=signprep_proof"`
}

// WireType returns the canonical wire type identifier for presignRound3Payload.
func (presignRound3Payload) WireType() string { return presignRound3PayloadWireType }

// WireVersion returns the wire format version for presignRound3Payload.
func (presignRound3Payload) WireVersion() uint16 { return tss.Version }

type signPartialPayload struct {
	S                   *big.Int `wire:"1,biguint,max_bytes=scalar"`
	PresignTranscript   []byte   `json:"presign_transcript" wire:"2,bytes,len=32"`
	PresignContext      []byte   `json:"presign_context" wire:"3,bytes,len=32"`
	DigestHash          []byte   `json:"digest_hash" wire:"4,bytes,len=32"`
	PartialEquationHash []byte   `json:"partial_equation_hash" wire:"5,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for signPartialPayload.
func (signPartialPayload) WireType() string { return signPartialPayloadWireType }

// WireVersion returns the wire format version for signPartialPayload.
func (signPartialPayload) WireVersion() uint16 { return tss.Version }

// Guard returns the session's envelope guard for use by transport adapters.
func (s *PresignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *PresignSession) validateInbound(env tss.Envelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.sessionID, tss.PartySet(s.signers), s.key.Party)
}

// HandlePresignMessage validates and applies one presign envelope.
// It dispatches to per-round handlers that each follow the template:
// parse → policy validate → cryptographic verify → mutate state → emit.
func (s *PresignSession) HandlePresignMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil presign session")
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

// Presign returns the completed local presign record and transfers ownership to
// the caller.
//
// Presign enforces single retrieval: after the first successful call the session
// will not hand out another copy. Callers must store the returned presign for
// signing and persistence. Subsequent calls return (nil, false).
func (s *PresignSession) Presign() (*Presign, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
		return nil, false
	}
	if s.presignReturned {
		return nil, false
	}
	if s.presign == nil {
		return nil, false
	}
	s.presignReturned = true
	p := s.presign
	s.presign = nil
	return p, true
}
