package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/tssrun"
)

const (
	presignTranscriptHashLabel = "cggmp21-secp256k1-presign-transcript-v1"
	presignContextHashLabel    = "cggmp21-secp256k1-presign-context-v1"
	presignRound1EchoLabel     = "cggmp21-secp256k1-presign-round1-echo-v1"
	presignRound1PublicLabel   = "cggmp21-secp256k1-presign-round1-public-v1"
	signMessageDigestLabel     = "cggmp21-secp256k1-sign-message-v1"
	mtaResponseEvidenceLabel   = "cggmp21-secp256k1-mta-response-evidence-v1"

	// DefaultLifecycleStoreTimeout bounds durable presign and online-sign
	// lifecycle calls after local validation has completed.
	DefaultLifecycleStoreTimeout = 5 * time.Second
)

// ErrSignAttemptCorrupt reports an invalid or inconsistent durable attempt.
var ErrSignAttemptCorrupt = errors.New("sign attempt record corrupt")

var errPresignSignerMissing = errors.New("sender is not in signer set")

// SignRuntime contains this process's local execution dependencies for
// CGGMP21 online signing. These values are not shared intent and are not part
// of the sign plan digest.
type SignRuntime struct {
	Local               tss.LocalConfig
	Guard               *tss.EnvelopeGuard
	LifecycleStore      tssrun.LifecycleStore
	Binding             tssrun.GenerationBinding
	PresignID           string
	AttemptID           string
	DeliveryPolicy      SignAttemptDeliveryPolicy
	DurableStoreTimeout time.Duration
}

// Presign contains one local offline signing record and must be consumed once.
// MarshalBinary maps only an available record to the canonical private wire
// shape; claim state is runtime-only and is not encoded. JSON encoding is
// intentionally rejected by [Presign.MarshalJSON] to prevent accidental
// exposure of secret material. Its fields are opaque and copy-returning
// accessors expose public metadata without permitting mutation of the
// validated record.
//
// A shallow Go copy of Presign is another handle to the same one-use lifecycle
// state, including the consumed claim and secret material.
type Presign struct {
	state *presignState
}

type presignState struct {
	Party                tss.PartyID                   `wire:"1,u32"`
	Threshold            int                           `wire:"2,u32"`
	Signers              tss.PartySet                  `wire:"3,u32list,max_items=signers"`
	PresignID            []byte                        `wire:"4,bytes,len=32"`
	EpochID              []byte                        `wire:"5,bytes,len=32"`
	Gamma                *secp.Point                   `wire:"6,custom,len=33"`
	LittleR              secp.Scalar                   `wire:"7,custom,len=32"`
	KShare               *secret.Scalar                `wire:"8,custom,len=32"` // Normalized k_i/delta.
	ChiShare             *secret.Scalar                `wire:"9,custom,len=32"` // Normalized chi_i/delta; may be zero.
	Commitments          []normalizedPresignCommitment `wire:"10,recordlist,max_items=signers"`
	TranscriptHash       []byte                        `wire:"11,bytes,len=32"`
	Context              tss.SigningContext            `wire:"12,nested"`
	ContextHash          []byte                        `wire:"13,bytes,len=32"`
	PublicKey            *secp.Point                   `wire:"14,custom,len=33"`
	KeygenTranscriptHash []byte                        `wire:"15,bytes,len=32"`
	PartiesHash          []byte                        `wire:"16,bytes,len=32"`
	PlanHash             []byte                        `wire:"17,bytes,len=32"`
	SecurityParams       SecurityParams                `wire:"18,record"`
	Derivation           *tss.DerivationResult         `wire:"19,record"` // Empty-path binding to the exact lifecycle generation public key and chain code.
	Epoch                *EpochContext                 `wire:"20,record"` // Full public auxiliary epoch, including SID, RID, dynamic identifiers, and source epoch.

	Consumed atomicBool             `wire:"-"`
	attempt  *presignAttemptBinding `wire:"-"`
}

// PartyID returns the owner of the local presign share.
func (p *Presign) PartyID() tss.PartyID {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.Party
}

// Threshold returns the signing threshold.
func (p *Presign) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.Threshold
}

// PublicMetadata returns a caller-owned snapshot of non-secret presign metadata
// that is not scoped to a single signer.
func (p *Presign) PublicMetadata() (PresignPublicMetadata, bool) {
	if p == nil || p.state == nil {
		return PresignPublicMetadata{}, false
	}
	gammaBytes, err := secp.PointBytes(p.state.Gamma)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	publicKeyBytes, err := secp.PointBytes(p.state.PublicKey)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	if p.state.Epoch == nil || p.state.Derivation == nil {
		return PresignPublicMetadata{}, false
	}
	if err := p.state.Epoch.ValidateWithLimits(DefaultLimits()); err != nil {
		return PresignPublicMetadata{}, false
	}
	lifecycleSlot, err := PresignSlotID(p.state.PresignID)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	sourceEpochID, _ := p.state.Epoch.SourceEpochIDBytes()
	return PresignPublicMetadata{
		SecurityParams:       p.state.SecurityParams,
		Party:                p.state.Party,
		Threshold:            p.state.Threshold,
		Signers:              p.state.Signers.Clone(),
		PresignID:            bytes.Clone(p.state.PresignID),
		SID:                  p.state.Epoch.SID,
		RID:                  p.state.Epoch.RID,
		EpochID:              bytes.Clone(p.state.EpochID),
		Identifiers:          tss.CloneSlice(p.state.Epoch.Identifiers),
		SourceEpochID:        sourceEpochID,
		Epoch:                p.state.Epoch.Clone(),
		LifecycleSlot:        lifecycleSlot,
		Gamma:                gammaBytes,
		R:                    bytes.Clone(gammaBytes),
		LittleR:              p.state.LittleR.Bytes(),
		TranscriptHash:       bytes.Clone(p.state.TranscriptHash),
		Context:              p.state.Context.Clone(),
		ContextHash:          bytes.Clone(p.state.ContextHash),
		Derivation:           p.state.Derivation.Clone(),
		VerificationKey:      p.verificationKey(),
		PlanHash:             bytes.Clone(p.state.PlanHash),
		PublicKey:            publicKeyBytes,
		KeygenTranscriptHash: bytes.Clone(p.state.KeygenTranscriptHash),
		PartiesHash:          bytes.Clone(p.state.PartiesHash),
	}, true
}

// SecurityParams returns the cryptographic profile persisted with the presign.
func (p *Presign) SecurityParams() SecurityParams {
	if p == nil || p.state == nil {
		return SecurityParams{}
	}
	return p.state.SecurityParams
}

// MarshalJSON rejects default JSON encoding of secret-bearing presign records.
func (p Presign) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 presign contains secret material; use MarshalBinary")
}

// MarshalBinary encodes an available presign record without changing its
// lifecycle state. Bound, discarded, or destroyed presigns cannot be encoded.
func (p *Presign) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes an available presign without changing its
// lifecycle state, using explicit local limits.
func (p *Presign) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return p.marshalWireMessageWithLimits(limits)
}

// LifecycleMetadata returns the canonical public Figure 10 verification,
// generation-derivation, full auxiliary-epoch, and canonical presign-slot
// context that must accompany this presign in a tssrun LifecycleStore.
func (p *Presign) LifecycleMetadata() ([]byte, error) {
	return p.LifecycleMetadataWithLimits(DefaultLimits())
}

// LifecycleMetadataWithLimits returns the canonical lifecycle public context
// using explicit local resource limits.
func (p *Presign) LifecycleMetadataWithLimits(limits Limits) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil presign")
	}
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	context := signAttemptPublicContextFromPresign(p)
	defer context.destroy()
	return marshalSignAttemptPublicContext(context, limits)
}

// UnmarshalBinary decodes a canonical CGGMP21 presign record with size caps.
func (p *Presign) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical presign record into the
// receiver using explicit local resource limits.
func (p *Presign) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if len(in) == 0 {
		return errors.New("empty presign")
	}
	if len(in) > limits.State.MaxSerializedPresignBytes {
		return fmt.Errorf("presign too large: %d > %d", len(in), limits.State.MaxSerializedPresignBytes)
	}
	var decoded Presign
	if err := decoded.unmarshalWireMessageWithLimits(in, limits,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedPresignBytes)),
	); err != nil {
		return err
	}
	p.state = decoded.state
	return nil
}

func (p *Presign) verificationKey() []byte {
	if p == nil || p.state == nil {
		return nil
	}
	if p.state.Derivation != nil {
		return p.state.Derivation.VerificationKeyBytes()
	}
	encoded, err := secp.PointBytes(p.state.PublicKey)
	if err != nil {
		return nil
	}
	return encoded
}

// Validate checks the complete normalized Figure 8 artifact, including local
// secret openings and aggregate commitment equations, under production limits.
func (p *Presign) Validate() error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if !isProductionSecurityParams(p.state.SecurityParams) {
		return errors.New("presign uses non-production security params")
	}
	return p.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks the complete normalized Figure 8 artifact using
// explicit local limits and the security profile persisted in the artifact.
// Validation does not change one-use lifecycle state.
func (p *Presign) ValidateWithLimits(limits Limits) error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if err := p.state.SecurityParams.Validate(); err != nil {
		return fmt.Errorf("invalid presign security params: %w", err)
	}
	if p.state.Consumed.Bool == nil {
		return errors.New("presign claim state unavailable")
	}
	if p.state.attempt == nil {
		return errors.New("presign attempt state unavailable")
	}
	if p.state.Threshold <= 0 || p.state.Threshold > len(p.state.Signers) {
		return errors.New("invalid presign threshold")
	}
	if len(p.state.Signers) > limits.Threshold.MaxSigners {
		return fmt.Errorf("too many presign signers: %d > %d", len(p.state.Signers), limits.Threshold.MaxSigners)
	}
	if err := limits.Threshold.ValidateThreshold(p.state.Threshold, len(p.state.Signers)); err != nil {
		return err
	}
	if err := wire.ValidateStrictSortedIDs(p.state.Signers); err != nil {
		return err
	}
	if !tss.ContainsParty(p.state.Signers, p.state.Party) {
		return errors.New("presign party is not in signer set")
	}
	if err := validateRequiredPlanID("presign id", p.state.PresignID); err != nil {
		return err
	}
	if err := validateRequiredPlanID("presign epoch id", p.state.EpochID); err != nil {
		return err
	}
	if _, err := secp.PointBytes(p.state.Gamma); err != nil {
		return fmt.Errorf("invalid presign Gamma: %w", err)
	}
	if p.state.LittleR.IsZero() {
		return errors.New("invalid little r: zero")
	}
	if !p.state.LittleR.Equal(secp.ScalarFromFieldElement(p.state.Gamma.X)) {
		return errors.New("presign little r does not match Gamma")
	}
	kTilde, err := secpScalarFromSecret(p.state.KShare)
	if err != nil {
		return fmt.Errorf("invalid normalized k share: %w", err)
	}
	chiTilde, err := secpScalarFromSecretAllowZero(p.state.ChiShare)
	if err != nil {
		return fmt.Errorf("invalid chi share: %w", err)
	}
	if len(p.state.TranscriptHash) != sha256.Size {
		return errors.New("invalid presign transcript hash")
	}
	if err := validatePresignContext(p.state.Context); err != nil {
		return err
	}
	if len(p.state.Context.Derivation.Path) != 0 || len(p.state.Context.Derivation.ResolvedPath) != 0 {
		return errors.New("presign contains a request-time derivation path")
	}
	if len(p.state.ContextHash) != sha256.Size {
		return errors.New("invalid presign context hash")
	}
	if len(p.state.PlanHash) != sha256.Size {
		return errors.New("invalid presign plan hash")
	}
	if _, err := secp.PointBytes(p.state.PublicKey); err != nil {
		return fmt.Errorf("invalid presign public key binding: %w", err)
	}
	if len(p.state.KeygenTranscriptHash) != sha256.Size {
		return errors.New("invalid presign keygen transcript hash binding")
	}
	if len(p.state.PartiesHash) != sha256.Size {
		return errors.New("invalid presign party-set hash binding")
	}
	if err := validatePresignGenerationBinding(p.state, limits); err != nil {
		return err
	}
	if !bytes.Equal(presignContextHash(p.state.Context), p.state.ContextHash) {
		return errors.New("presign context hash mismatch")
	}
	if err := validateNormalizedPresignArtifact(p.state.Signers, p.state.Commitments, p.state.Party, p.state.Gamma, p.state.PublicKey, kTilde, chiTilde); err != nil {
		return fmt.Errorf("invalid normalized presign artifact: %w", err)
	}
	return nil
}

// Destroy marks the presign consumed and clears its local secret shares.
func (p *Presign) Destroy() {
	if p == nil || p.state == nil {
		return
	}
	if p.state.Consumed.Bool != nil {
		p.state.Consumed.Store(true)
	}
	if p.state.attempt != nil {
		p.state.attempt.discard()
	}
	if p.state.KShare != nil {
		p.state.KShare.Destroy()
	}
	if p.state.ChiShare != nil {
		p.state.ChiShare.Destroy()
	}
	for i := range p.state.Commitments {
		p.state.Commitments[i].destroy()
	}
	p.state.Commitments = nil
	clear(p.state.PresignID)
	clear(p.state.EpochID)
	p.state.Gamma = nil
	p.state.PublicKey = nil
	clear(p.state.TranscriptHash)
	clear(p.state.ContextHash)
	clear(p.state.KeygenTranscriptHash)
	clear(p.state.PartiesHash)
	clear(p.state.PlanHash)
	if p.state.Derivation != nil {
		p.state.Derivation.Destroy()
		p.state.Derivation = nil
	}
	p.state.Epoch = nil
}

// PresignSession tracks the CGGMP21-style offline presign exchange.
type PresignSession struct {
	mu sync.Mutex

	key              *KeyShare             // Session-owned exact generation decoded from LifecycleStore.
	ownsKey          bool                  // Whether abort/completion must destroy key.
	sessionID        tss.SessionID         // Presign session ID bound into envelopes and planHash.
	config           tss.ThresholdConfig   // Local threshold runtime view for signer membership and transport.
	log              tss.Logger            // Optional protocol logger.
	limits           Limits                // Local fail-closed resource policy.
	securityParams   SecurityParams        // Cryptographic profile inherited from the key share.
	signers          tss.PartySet          // Canonical signer set participating in this presign.
	context          tss.SigningContext    // Normalized context bound to the resulting presign.
	contextHash      []byte                // Hash of context; echoed through presign/sign validation.
	presignID        []byte                // Caller-coordinated one-use inventory identity.
	epochID          []byte                // Exact auxiliary epoch used by every proof and payload.
	derivation       *tss.DerivationResult // Resolved child key/path; destroyed if the session aborts.
	planHash         []byte                // Digest every presign round payload must echo.
	paillier         *pai.PrivateKey       // Local Paillier private key used for MtA decryption.
	guard            *tss.EnvelopeGuard    // Transport replay, identity, and policy guard.
	lifecycleStore   tssrun.LifecycleStore // Durable exact-generation and available-presign boundary.
	lifecycleLease   tssrun.RunLease       // Active RunPresign lease held until atomic persistence or abort.
	lifecycleTimeout time.Duration         // Bound for durable lifecycle operations.
	leaseFinished    bool                  // True after atomic presign commit or durable abort.

	kShare    *secret.Scalar // Local nonce share k, secret-bearing until presign completes or aborts.
	gamma     *secret.Scalar // Local gamma nonce share, secret-bearing until presign completes or aborts.
	a         *secret.Scalar // Figure 8 A_i ElGamal exponent, retained through round 3.
	b         *secret.Scalar // Figure 8 B_i ElGamal exponent, retained through round 2.
	xBar      *secret.Scalar // Local additive signing share adjusted for HD derivation.
	gammaComm []byte         // Public commitment to gamma used in round-1 proof binding.
	xBarComm  []byte         // Public commitment to xBar used in round-3 proof binding.

	partyIndex map[tss.PartyID]int // Index into parties; initialized once at StartPresign.
	parties    []presignPartyState // Ordered by canonical signer set.

	startOpening *mta.StartOpening // Local MtA opening material; secret-bearing until round 2 completes.
	gammaOpening *mta.StartOpening // Local encrypted gamma opening retained until Figure 8 completes.

	round2Sent       bool // Whether this party already emitted round-2 MtA responses.
	round3Sent       bool // Whether this party already emitted round-3 verification material.
	identifying      bool // Whether a Figure 8 red alert activated Figure 9.
	redAlertKind     presignRedAlertKind
	redAlertDigest   []byte
	redAlertPayloads map[tss.PartyID]presignRedAlertPayload
	completed        bool              // Terminal success flag; persisted descriptor is available once true.
	aborted          bool              // Terminal failure/destruction flag.
	persistedPresign *PersistedPresign // Public-only descriptor installed after the atomic store commit.
}

type presignPartyState struct {
	id tss.PartyID

	round1 presignRound1State
	round2 presignRound2State
	round3 presignRound3State
	mta    presignMTAState
}

type presignRound1State struct {
	payload       presignRound1Payload
	havePayload   bool
	proof         presignRound1ProofPayload
	proofEnvelope tss.Envelope
	haveProof     bool
	verified      bool
}

type presignRound2State struct {
	payload           presignRound2Payload
	payloadEnvelope   tss.Envelope
	havePayload       bool
	outboundHash      []byte
	outboundEnvelope  tss.Envelope
	outboundSigma     mta.ResponseMessage
	haveOutboundSigma bool
	outboundDelta     mta.ResponseMessage
	haveOutboundDelta bool
}

type presignRound3State struct {
	delta       *secret.Scalar
	chi         *secret.Scalar // Local-only; nil for remote parties.
	deltaPoint  []byte
	sPoint      []byte
	proof       zkpai.ElogProof
	havePayload bool
}

type presignMTAState struct {
	alphaDelta   *secret.Scalar
	betaDelta    *secret.Scalar
	alphaSigma   *secret.Scalar
	betaSigma    *secret.Scalar
	deltaOpening *mta.ResponseOpening
	sigmaOpening *mta.ResponseOpening
}

func newPresignPartyStates(signers tss.PartySet) ([]presignPartyState, map[tss.PartyID]int) {
	parties := make([]presignPartyState, len(signers))
	index := make(map[tss.PartyID]int, len(signers))
	for i, id := range signers {
		parties[i] = presignPartyState{id: id}
		index[id] = i
	}
	return parties, index
}

func (s *PresignSession) partyState(id tss.PartyID) (*presignPartyState, bool) {
	if s == nil {
		return nil, false
	}
	i, ok := s.partyIndex[id]
	if !ok {
		return nil, false
	}
	return &s.parties[i], true
}

// abort marks the presign session aborted and clears all secret-bearing
// accumulated state (nonce scalars, Paillier key, MtA shares, delta shares,
// round payloads, start opening, and any completed presign record).
func (s *PresignSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.completed = false
	s.identifying = false
	clear(s.redAlertDigest)
	s.redAlertDigest = nil
	for party, payload := range s.redAlertPayloads {
		payload.Destroy()
		delete(s.redAlertPayloads, party)
	}
	s.redAlertPayloads = nil
	s.kShare.Destroy()
	s.gamma.Destroy()
	s.a.Destroy()
	s.b.Destroy()
	s.xBar.Destroy()
	s.kShare = nil
	s.gamma = nil
	s.a = nil
	s.b = nil
	s.xBar = nil
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	for i := range s.parties {
		s.parties[i].destroy()
	}
	clear(s.partyIndex)
	s.parties = nil
	if s.derivation != nil {
		s.derivation.Destroy()
		s.derivation = nil
	}
	if s.startOpening != nil {
		s.startOpening.Destroy()
		s.startOpening = nil
	}
	if s.gammaOpening != nil {
		s.gammaOpening.Destroy()
		s.gammaOpening = nil
	}
	if s.persistedPresign != nil {
		s.persistedPresign.destroy()
		s.persistedPresign = nil
	}
	if s.ownsKey && s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
}

func (p *presignPartyState) destroy() {
	if p == nil {
		return
	}
	p.round1.destroy()
	p.round2.destroy()
	p.round3.destroy()
	p.mta.destroy()
	*p = presignPartyState{}
}

func (r *presignRound1State) destroy() {
	if r == nil {
		return
	}
	clear(r.payload.EncK)
	clear(r.payload.EncGamma)
	clear(r.payload.Y)
	clear(r.payload.A1)
	clear(r.payload.A2)
	clear(r.payload.B1)
	clear(r.payload.B2)
	clear(r.payload.EpochID)
	clear(r.payload.PresignID)
	if r.payload.PaillierPublicKey != nil {
		secret.ClearBigInt(r.payload.PaillierPublicKey.N)
		secret.ClearBigInt(r.payload.PaillierPublicKey.G)
		secret.ClearBigInt(r.payload.PaillierPublicKey.NSquared)
	}
	clear(r.proof.PublicRound1Hash)
	r.proof.EncKProof.Destroy()
	r.proof.EncGammaProof.Destroy()
	*r = presignRound1State{}
}

func (r *presignRound2State) destroy() {
	if r == nil {
		return
	}
	clear(r.payload.Gamma)
	r.payload.GammaProof.Destroy()
	clear(r.payload.Delta.Ciphertext)
	r.payload.Delta.Proof.Destroy()
	clear(r.payload.Sigma.Ciphertext)
	r.payload.Sigma.Proof.Destroy()
	clear(r.payload.Round1Echo)
	clear(r.payload.EpochID)
	clear(r.payload.PresignID)
	clear(r.outboundHash)
	r.outboundSigma.Destroy()
	r.outboundDelta.Destroy()
	clearEnvelope(&r.payloadEnvelope)
	clearEnvelope(&r.outboundEnvelope)
	*r = presignRound2State{}
}

func clearEnvelope(env *tss.Envelope) {
	if env == nil {
		return
	}
	clear(env.Payload)
	clear(env.SenderSignature)
	*env = tss.Envelope{}
}

func (r *presignRound3State) destroy() {
	if r == nil {
		return
	}
	if r.delta != nil {
		r.delta.Destroy()
	}
	if r.chi != nil {
		r.chi.Destroy()
	}
	clear(r.deltaPoint)
	clear(r.sPoint)
	r.proof.Destroy()
	*r = presignRound3State{}
}

func (m *presignMTAState) destroy() {
	if m == nil {
		return
	}
	if m.alphaDelta != nil {
		m.alphaDelta.Destroy()
	}
	if m.betaDelta != nil {
		m.betaDelta.Destroy()
	}
	if m.alphaSigma != nil {
		m.alphaSigma.Destroy()
	}
	if m.betaSigma != nil {
		m.betaSigma.Destroy()
	}
	if m.deltaOpening != nil {
		m.deltaOpening.Destroy()
	}
	if m.sigmaOpening != nil {
		m.sigmaOpening.Destroy()
	}
	*m = presignMTAState{}
}

// SignSession tracks the online threshold ECDSA signing exchange.
type SignSession struct {
	mu sync.Mutex

	key              *KeyShare                   // Session-owned exact generation decoded from LifecycleStore.
	ownsKey          bool                        // Whether terminal cleanup must destroy key.
	verification     signAttemptPublicContext    // Public Figure 10 context; never contains normalized secret shares.
	sessionID        tss.SessionID               // Online signing session ID for partial-signature envelopes.
	guard            *tss.EnvelopeGuard          // Transport replay, identity, and policy guard.
	log              tss.Logger                  // Optional protocol logger.
	limits           Limits                      // Local fail-closed resource policy.
	digest           []byte                      // Context-bound message digest signed by ECDSA.
	planHash         []byte                      // Digest every sign partial must echo.
	publicKey        []byte                      // Verification key used for final ECDSA self-checking.
	partials         map[tss.PartyID]secp.Scalar // Validated ECDSA partial scalars keyed by signer.
	partialEnvelopes map[tss.PartyID]tss.Envelope
	completed        bool                     // Terminal success flag; signature is available once true.
	aborted          bool                     // Terminal failure/destruction flag.
	signature        *Signature               // Final aggregated signature, cleared by Destroy.
	attempt          tssrun.SignAttemptRecord // Durable one-use attempt/outbox record.
	outbox           signAttemptOutbox        // Immutable recovery identity and exact local broadcast.
	coordinator      *signAttemptCoordinator  // Durable one-use attempt and outbox coordinator.
	coordinatorCtx   context.Context          // Detached context used for handler-triggered durable effects.
	deliveryAcks     []tss.BroadcastAck       // Verified locally; only a full certificate becomes durable.
}

// abort marks the signing session aborted and clears secret-bearing
// accumulated state (signing partials and message digest).
func (s *SignSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	clearScalarMap(s.partials)
	clear(s.digest)
	s.digest = nil
	for id, env := range s.partialEnvelopes {
		clearEnvelope(&env)
		delete(s.partialEnvelopes, id)
	}
	for i := range s.deliveryAcks {
		clear(s.deliveryAcks[i].Signature)
	}
	s.deliveryAcks = nil
	s.verification.destroy()
	clearSignAttemptOutbox(&s.outbox)
	if s.ownsKey && s.key != nil {
		s.key.Destroy()
		s.key = nil
		s.ownsKey = false
	}
}

type presignRound1Payload struct {
	EncK              []byte         `json:"enc_k" wire:"1,bytes,max_bytes=paillier_ciphertext"`
	EncGamma          []byte         `json:"enc_gamma" wire:"2,bytes,max_bytes=paillier_ciphertext"`
	Y                 []byte         `json:"y" wire:"3,bytes,len=33"`
	A1                []byte         `json:"a1" wire:"4,bytes,len=33"`
	A2                []byte         `json:"a2" wire:"5,bytes,len=33"`
	B1                []byte         `json:"b1" wire:"6,bytes,len=33"`
	B2                []byte         `json:"b2" wire:"7,bytes,len=33"`
	PaillierPublicKey *pai.PublicKey `json:"paillier_public_key" wire:"8,nested,max_bytes=paillier_public_key"`
	PlanHash          []byte         `json:"plan_hash" wire:"9,bytes,len=32"`
	EpochID           []byte         `json:"epoch_id" wire:"10,bytes,len=32"`
	PresignID         []byte         `json:"presign_id" wire:"11,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound1Payload.
func (presignRound1Payload) WireType() string { return presignRound1PayloadWireType }

// WireVersion returns the wire format version for presignRound1Payload.
func (presignRound1Payload) WireVersion() uint16 { return presignRound1PayloadWireVersion }

type presignRound1ProofPayload struct {
	PublicRound1Hash []byte            `json:"public_round1_hash" wire:"1,bytes,len=32"`
	EncKProof        zkpai.EncElgProof `json:"enc_k_proof" wire:"2,nested,max_bytes=zk_proof"`
	EncGammaProof    zkpai.EncElgProof `json:"enc_gamma_proof" wire:"3,nested,max_bytes=zk_proof"`
	PlanHash         []byte            `json:"plan_hash" wire:"4,bytes,len=32"`
	EpochID          []byte            `json:"epoch_id" wire:"5,bytes,len=32"`
	PresignID        []byte            `json:"presign_id" wire:"6,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound1ProofPayload.
func (presignRound1ProofPayload) WireType() string { return presignRound1ProofPayloadWireType }

// WireVersion returns the wire format version for presignRound1ProofPayload.
func (presignRound1ProofPayload) WireVersion() uint16 {
	return presignRound1ProofPayloadWireVersion
}

type presignRound2Payload struct {
	Gamma      []byte              `json:"gamma" wire:"1,bytes,len=33"`
	GammaProof zkpai.ElogProof     `json:"gamma_proof" wire:"2,nested,max_bytes=zk_proof"`
	Delta      mta.ResponseMessage `json:"delta" wire:"3,nested,max_bytes=mta_response"`
	Sigma      mta.ResponseMessage `json:"sigma" wire:"4,nested,max_bytes=mta_response"`
	Round1Echo []byte              `json:"round1_echo" wire:"5,bytes,len=32"`
	PlanHash   []byte              `json:"plan_hash" wire:"6,bytes,len=32"`
	EpochID    []byte              `json:"epoch_id" wire:"7,bytes,len=32"`
	PresignID  []byte              `json:"presign_id" wire:"8,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound2Payload.
func (presignRound2Payload) WireType() string { return presignRound2PayloadWireType }

// WireVersion returns the wire format version for presignRound2Payload.
func (presignRound2Payload) WireVersion() uint16 { return presignRound2PayloadWireVersion }

type presignRound3Payload struct {
	Delta      *secret.Scalar  `json:"-" wire:"1,custom,len=32"`
	S          []byte          `json:"s" wire:"2,bytes,max_bytes=point"`
	DeltaPoint []byte          `json:"delta_point" wire:"3,bytes,max_bytes=point"`
	Proof      zkpai.ElogProof `json:"proof" wire:"4,nested,max_bytes=zk_proof"`
	PlanHash   []byte          `json:"plan_hash" wire:"5,bytes,len=32"`
	EpochID    []byte          `json:"epoch_id" wire:"6,bytes,len=32"`
	PresignID  []byte          `json:"presign_id" wire:"7,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound3Payload.
func (presignRound3Payload) WireType() string { return presignRound3PayloadWireType }

// WireVersion returns the wire format version for presignRound3Payload.
func (presignRound3Payload) WireVersion() uint16 { return presignRound3PayloadWireVersion }

type signPartialPayload struct {
	S                   *secret.Scalar `json:"-" wire:"1,custom,len=32"`
	PresignID           []byte         `json:"presign_id" wire:"2,bytes,len=32"`
	EpochID             []byte         `json:"epoch_id" wire:"3,bytes,len=32"`
	PresignTranscript   []byte         `json:"presign_transcript" wire:"4,bytes,len=32"`
	PresignContext      []byte         `json:"presign_context" wire:"5,bytes,len=32"`
	DigestHash          []byte         `json:"digest_hash" wire:"6,bytes,len=32"`
	PartialEquationHash []byte         `json:"partial_equation_hash" wire:"7,bytes,len=32"`
	PlanHash            []byte         `json:"plan_hash" wire:"8,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for signPartialPayload.
func (signPartialPayload) WireType() string { return signPartialPayloadWireType }

// WireVersion returns the wire format version for signPartialPayload.
func (signPartialPayload) WireVersion() uint16 { return signPartialPayloadWireVersion }

// Guard returns the session's envelope guard for use by transport adapters.
func (s *PresignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *PresignSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.signers, s.key.state.Party)
}

// Handle validates and applies one presign envelope.
// It dispatches to per-round transitions that decode, validate, verify,
// prepare, commit, and only then return effects.
func (s *PresignSession) Handle(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if s == nil {
		return nil, errors.New("nil presign session")
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
		if errors.Is(err, errUnattributedPresignFailure) || shouldAbortSession(err) {
			err = s.abortPresignRun(err)
		}
	}()
	// Authenticate the envelope and enforce its delivery policy before decoding
	// or inspecting protocol readiness, but do not reserve the replay slot yet.
	// Each transition builder stages every fallible next-round effect first; the
	// exact replay slot is committed only immediately before the infallible state
	// commit below.
	if err := tss.ValidateInboundWithoutReplay(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.signers, s.key.state.Party); err != nil {
		return nil, err
	}
	if !tss.ContainsParty(s.signers, base.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}
	st, ok := s.partyState(base.From)
	if !ok {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}

	switch base.PayloadType {
	case payloadPresignRound1:
		if base.Round != presignStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round1 payload in wrong round"))
		}
		if st.round1.havePayload {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate presign round1"))
		}
		tx, err := s.buildAcceptPresignRound1PayloadTx(base)
		if err != nil {
			return nil, err
		}
		return applyPresignTransition(s, env, tx)

	case payloadPresignRound1Proof:
		if base.Round != presignStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round1 proof payload in wrong round"))
		}
		if base.From == s.key.state.Party {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("self presign round1 proof is not expected"))
		}
		if st.round1.haveProof {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate presign round1 proof"))
		}
		tx, err := s.buildAcceptPresignRound1ProofTx(base)
		if err != nil {
			return nil, err
		}
		return applyPresignTransition(s, env, tx)

	case payloadPresignRound2:
		if base.Round != presignRound2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round2 payload in wrong round"))
		}
		if st.round2.havePayload {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate presign round2"))
		}
		if err := s.validatePresignInboundReadiness(base); err != nil {
			return nil, err
		}
		tx, err := s.buildAcceptPresignRound2Tx(base)
		if err != nil {
			return nil, err
		}
		return applyPresignTransition(s, env, tx)

	case payloadPresignRound3:
		if base.Round != presignRound3 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round3 payload in wrong round"))
		}
		if st.round3.havePayload {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate Figure 8 round3 payload"))
		}
		if err := s.validatePresignInboundReadiness(base); err != nil {
			return nil, err
		}
		tx, err := s.buildAcceptPresignRound3Tx(base)
		if err != nil {
			return nil, err
		}
		return applyPresignTransition(s, env, tx)

	case payloadPresignRedAlert:
		if base.Round != presignRedAlertRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("figure 9 payload in wrong round"))
		}
		if !s.identifying {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("figure 9 red-alert phase is not active"))
		}
		if _, exists := s.redAlertPayloads[base.From]; exists {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate Figure 9 payload"))
		}
		tx, err := s.buildAcceptPresignRedAlertTx(base)
		if err != nil {
			return nil, err
		}
		return applyPresignTransition(s, env, tx)

	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
	}
}

//nolint:unparam // This helper returns the Handle result shape; duplicate rejection intentionally emits no envelopes.
func (s *PresignSession) rejectAcceptedPresignDuplicate(env tss.InboundEnvelope, cause error) ([]tss.Envelope, error) {
	base := env.Envelope()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, cause)
}

func applyPresignTransition(s *PresignSession, env tss.InboundEnvelope, tx sessionTransition[PresignSession]) ([]tss.Envelope, error) {
	defer tx.cleanupOnReject()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	effects, err := tx.apply(s)
	if err != nil {
		return nil, err
	}
	tx.markCommitted()
	return effects.envelopes, nil
}

// Presign returns a public-only descriptor for the completed presign after its
// secret record is atomically available in the lifecycle store. The descriptor
// is independently owned and can be retrieved repeatedly; it never contains
// nonce shares or other signing witnesses.
func (s *PresignSession) Presign() (PersistedPresign, bool) {
	if s == nil {
		return PersistedPresign{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed || s.persistedPresign == nil {
		return PersistedPresign{}, false
	}
	return newPersistedPresign(s.persistedPresign.slot, s.persistedPresign.metadata), true
}
