package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/signprep"
)

const (
	presignTranscriptHashLabel = "cggmp21-secp256k1-presign-transcript-v1"
	presignContextHashLabel    = "cggmp21-secp256k1-presign-context-v1"
	presignRound1EchoLabel     = "cggmp21-secp256k1-presign-round1-echo-v1"
	presignRound1PublicLabel   = "cggmp21-secp256k1-presign-round1-public-v1"
	presignIDLabel             = "cggmp21-secp256k1-presign-id-v1"
	signMessageDigestLabel     = "cggmp21-secp256k1-sign-message-v1"
	mtaResponseEvidenceLabel   = "cggmp21-secp256k1-mta-response-evidence-v1"

	// DefaultSignAttemptStoreTimeout bounds durable sign-attempt store calls
	// after local validation has completed.
	DefaultSignAttemptStoreTimeout = 5 * time.Second
)

// PresignContext binds a presignature to the signing context where it may be consumed.
type PresignContext = tss.SigningContext

// ErrSignAttemptNotFound reports that no durable attempt exists for a presign.
var ErrSignAttemptNotFound = errors.New("sign attempt not found")

// ErrSignAttemptConflict reports that a presign is bound to another intent.
var ErrSignAttemptConflict = errors.New("sign attempt conflict")

// ErrSignAttemptOutcomeUnknown reports that an attempt commit may have succeeded.
var ErrSignAttemptOutcomeUnknown = errors.New("sign attempt commit outcome unknown")

// ErrSignAttemptNonDeterminism reports that one intent produced another attempt.
var ErrSignAttemptNonDeterminism = errors.New("sign attempt non-determinism")

// ErrSignAttemptBurned reports that a durable tombstone blocks the presign.
var ErrSignAttemptBurned = errors.New("sign attempt burned")

// ErrSignAttemptCorrupt reports an invalid or inconsistent durable attempt.
var ErrSignAttemptCorrupt = errors.New("sign attempt record corrupt")

var errPresignSignerMissing = errors.New("sender is not in signer set")

// SignAttemptStore is the durable one-use and outbox boundary for online
// signing. CommitSignAttempt must atomically bind one presign ID to one immutable
// intent and its exact canonical outbound envelope.
//
// CommitSignAttempt accepts an incomplete candidate, creates the attempt, or
// returns the existing exact attempt. ErrSignAttemptConflict, ErrSignAttemptBurned,
// and ErrSignAttemptNonDeterminism are consumed outcomes. Any other commit error
// has an unknown outcome: callers must retain the local binding and retry or
// resume only the same intent. LoadSignAttempt is for ResumeSign and inspection;
// it is not part of StartSign's linearization path.
// CompleteSignAttempt is idempotent and must make the final signature durable
// before returning success.
type SignAttemptStore interface {
	CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error)
	LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error)
	UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error)
	CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error)
	BurnPresign(ctx context.Context, burn SignAttemptBurn) error
}

// SignRequest is the context-bound online signing request for a persisted
// presignature. Message is hashed with the presign context before ECDSA.
type SignRequest struct {
	Context      PresignContext   `json:"context"`
	Message      []byte           `json:"message"`
	AttemptStore SignAttemptStore `json:"-"` // required durable attempt/outbox store

	// DurableStoreTimeout bounds durable commit/completion work after local
	// validation. Zero selects DefaultSignAttemptStoreTimeout.
	DurableStoreTimeout time.Duration `json:"-"`
}

// Clone returns a caller-owned copy of the sign request. The AttemptStore
// interface value is preserved by reference because it is an execution
// dependency, not mutable data.
func (r SignRequest) Clone() SignRequest {
	return SignRequest{
		Context:             r.Context.Clone(),
		Message:             slices.Clone(r.Message),
		AttemptStore:        r.AttemptStore,
		DurableStoreTimeout: r.DurableStoreTimeout,
	}
}

// Presign contains one local offline signing record and must be consumed once.
// MarshalBinary maps it to the canonical private wire record, including a
// consumed snapshot from the internal claim. JSON encoding is intentionally
// rejected by [Presign.MarshalJSON] to prevent accidental exposure of secret
// material. Its fields are opaque and copy-returning accessors expose public
// metadata without permitting mutation of the validated record.
//
// A shallow Go copy of Presign is another handle to the same one-use lifecycle
// state, including the consumed claim and secret material.
type Presign struct {
	state *presignState
}

type presignState struct {
	securityParams       SecurityParams         // Cryptographic profile inherited from the key share.
	party                tss.PartyID            // Local owner of this presign share.
	threshold            int                    // Number of signer partials required to complete ECDSA signing.
	signers              tss.PartySet           // Canonical signer set authorized for this presign.
	r                    *secp.Point            // Aggregate nonce point R.
	littleR              secp.Scalar            // ECDSA r scalar derived from R.
	transcriptHash       []byte                 // Cross-party presign transcript hash.
	context              PresignContext         // Normalized context bound before online signing.
	contextHash          []byte                 // Hash of context, used to reject cross-context reuse.
	derivation           *tss.DerivationResult  // Resolved child key/path; ChildPublicKey is the verification key.
	planHash             []byte                 // Digest of the presign lifecycle plan accepted by all signers.
	publicKey            *secp.Point            // Parent group public key before request-time HD derivation.
	keygenTranscriptHash []byte                 // Transcript hash of the keygen that produced publicKey.
	partiesHash          []byte                 // Hash of the full key-share participant set.
	verifyShares         []signVerifyShare      // Per-signer public verification material for online partials.
	kShare               *secret.Scalar         // Local nonce-share secret used once during online signing.
	chiShare             *secret.Scalar         // Local chi-share secret used once during online signing.
	delta                *secret.Scalar         // Local aggregate-delta share from presign completion.
	consumed             *atomic.Bool           // Shared in-process one-use marker across shallow copies.
	attempt              *presignAttemptBinding // Durable attempt binding/outbox state for one-use signing.
}

// PartyID returns the owner of the local presign share.
func (p *Presign) PartyID() tss.PartyID {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.party
}

// Threshold returns the signing threshold.
func (p *Presign) Threshold() int {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.threshold
}

// PublicMetadata returns a caller-owned snapshot of non-secret presign metadata
// that is not scoped to a single signer.
func (p *Presign) PublicMetadata() (PresignPublicMetadata, bool) {
	if p == nil || p.state == nil {
		return PresignPublicMetadata{}, false
	}
	rBytes, err := secp.PointBytes(p.state.r)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	publicKeyBytes, err := secp.PointBytes(p.state.publicKey)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	return PresignPublicMetadata{
		SecurityParams:       p.state.securityParams,
		Party:                p.state.party,
		Threshold:            p.state.threshold,
		Signers:              p.state.signers.Clone(),
		R:                    rBytes,
		LittleR:              p.state.littleR.Bytes(),
		TranscriptHash:       bytes.Clone(p.state.transcriptHash),
		Context:              p.state.context.Clone(),
		ContextHash:          bytes.Clone(p.state.contextHash),
		Derivation:           p.state.derivation.Clone(),
		VerificationKey:      p.verificationKey(),
		PlanHash:             bytes.Clone(p.state.planHash),
		PublicKey:            publicKeyBytes,
		KeygenTranscriptHash: bytes.Clone(p.state.keygenTranscriptHash),
		PartiesHash:          bytes.Clone(p.state.partiesHash),
	}, true
}

// SecurityParams returns the cryptographic profile persisted with the presign.
func (p *Presign) SecurityParams() SecurityParams {
	if p == nil || p.state == nil {
		return SecurityParams{}
	}
	return p.state.securityParams
}

// MarshalJSON rejects default JSON encoding of secret-bearing presign records.
func (p Presign) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 presign contains secret material; use MarshalBinary")
}

// MarshalBinary encodes the presign record using the object-level wire codec.
func (p *Presign) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the presign using explicit local limits.
func (p *Presign) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return p.MarshalWireMessage(wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
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
	if err := decoded.UnmarshalWireMessage(in,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedPresignBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	p.state = decoded.state
	return nil
}

// id returns a content-derived presign identifier suitable for use as an
// idempotency key in a durable [SignAttemptStore]. The returned hash is computed
// from all persisted presign fields, including secret material, and does not
// depend on the public transcript hash or the local consumed claim. Tampering with any
// persisted field changes the identifier, so a storage layer cannot alter the
// idempotency key independently of the presign contents.
func (p *Presign) id() []byte {
	if p == nil || p.state == nil {
		return nil
	}

	t := transcript.New(presignIDLabel)
	appendSecurityParamsTranscript(t, p.state.securityParams)
	t.AppendBytes("context_hash", p.state.contextHash)
	appendDerivationResultTranscript(t, p.state.derivation)
	t.AppendBytes("plan_hash", p.state.planHash)
	publicKeyBytes, _ := secp.PointBytes(p.state.publicKey)
	t.AppendBytes("public_key", publicKeyBytes)
	t.AppendBytes("keygen_transcript_hash", p.state.keygenTranscriptHash)
	t.AppendBytes("parties_hash", p.state.partiesHash)
	t.AppendUint32List("signers", p.state.signers)
	for _, vs := range p.state.verifyShares {
		kPointBytes, _ := vs.kPointBytes()
		chiPointBytes, _ := vs.chiPointBytes()
		proofBytes, _ := vs.proofBytes()
		t.AppendUint32("verify_share_party", vs.Party)
		t.AppendBytes("k_point", kPointBytes)
		t.AppendBytes("chi_point", chiPointBytes)
		proofHash := sha256.Sum256(proofBytes)
		t.AppendBytes("proof_hash", proofHash[:])
	}
	rBytes, _ := secp.PointBytes(p.state.r)
	t.AppendBytes("r_point", rBytes)
	t.AppendBytes("little_r", p.state.littleR.Bytes())
	t.AppendBytes("k_share", p.state.kShare.FixedBytes())
	t.AppendBytes("chi_share", p.state.chiShare.FixedBytes())
	t.AppendBytes("delta", p.state.delta.FixedBytes())
	return t.Sum()
}

func (p *Presign) verificationKey() []byte {
	if p == nil || p.state == nil || p.state.derivation == nil {
		return nil
	}
	return p.state.derivation.VerificationKeyBytes()
}

// Validate checks local presign structure and scalar/point encodings.
func (p *Presign) Validate() error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if !isProductionSecurityParams(p.state.securityParams) {
		return errors.New("presign uses non-production security params")
	}
	return p.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits validates a presign using explicit local limits and the
// security profile persisted in the artifact.
func (p *Presign) ValidateWithLimits(limits Limits) error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if err := p.state.securityParams.Validate(); err != nil {
		return fmt.Errorf("invalid presign security params: %w", err)
	}
	if p.state.consumed == nil {
		return errors.New("presign claim state unavailable")
	}
	if p.state.attempt == nil {
		return errors.New("presign attempt state unavailable")
	}
	if p.state.threshold <= 0 || p.state.threshold > len(p.state.signers) {
		return errors.New("invalid presign threshold")
	}
	if len(p.state.signers) > limits.Threshold.MaxSigners {
		return fmt.Errorf("too many presign signers: %d > %d", len(p.state.signers), limits.Threshold.MaxSigners)
	}
	if err := limits.Threshold.ValidateThreshold(p.state.threshold, len(p.state.signers)); err != nil {
		return err
	}
	if err := wire.ValidateStrictSortedIDs(p.state.signers); err != nil {
		return err
	}
	if !tss.ContainsParty(p.state.signers, p.state.party) {
		return errors.New("presign party is not in signer set")
	}
	if _, err := secp.PointBytes(p.state.r); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	if p.state.littleR.IsZero() {
		return errors.New("invalid little r: zero")
	}
	if _, err := secpScalarFromSecret(p.state.kShare); err != nil {
		return fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secpScalarFromSecret(p.state.chiShare); err != nil {
		return fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secpScalarFromSecret(p.state.delta); err != nil {
		return fmt.Errorf("invalid delta: %w", err)
	}
	if len(p.state.transcriptHash) != sha256.Size {
		return errors.New("invalid presign transcript hash")
	}
	if err := validatePresignContext(p.state.context); err != nil {
		return err
	}
	if len(p.state.contextHash) != sha256.Size {
		return errors.New("invalid presign context hash")
	}
	if err := validateDerivationResult(p.state.derivation, tss.DerivationSchemeBIP32Secp256k1); err != nil {
		return fmt.Errorf("invalid presign derivation: %w", err)
	}
	if len(p.state.derivation.AdditiveShift) > 0 {
		if _, err := secp.ScalarFromBytesAllowZero(p.state.derivation.AdditiveShift); err != nil {
			return fmt.Errorf("invalid additive shift: %w", err)
		}
	}
	if len(p.state.planHash) != sha256.Size {
		return errors.New("invalid presign plan hash")
	}
	if _, err := secp.PointBytes(p.state.publicKey); err != nil {
		return fmt.Errorf("invalid presign public key binding: %w", err)
	}
	if _, err := secp.PointFromBytes(p.state.derivation.ChildPublicKey); err != nil {
		return fmt.Errorf("invalid presign verification key binding: %w", err)
	}
	if len(p.state.keygenTranscriptHash) != sha256.Size {
		return errors.New("invalid presign keygen transcript hash binding")
	}
	if len(p.state.partiesHash) != sha256.Size {
		return errors.New("invalid presign party-set hash binding")
	}
	if !bytes.Equal(presignContextHash(p.state.context), p.state.contextHash) {
		return errors.New("presign context hash mismatch")
	}
	if err := validateSignVerifyShares(p.state.signers, p.state.verifyShares, limits); err != nil {
		return fmt.Errorf("invalid presign verify shares: %w", err)
	}
	return nil
}

// VerifySignMaterial performs a structural integrity check on all sign verify share
// entries in the presign record. Full cryptographic verification of each signprep
// proof happens during presign round 3 (with session ID bound). At StartSign time
// the presign transcript hash already binds every proof hash, so tampering would
// be caught by transcript mismatch. This method catches malformed proofs or
// invalid point encodings that may have resulted from storage corruption.
func (p *Presign) VerifySignMaterial() error {
	return p.VerifySignMaterialWithLimits(DefaultLimits())
}

// VerifySignMaterialWithLimits checks persisted signing verification material
// using explicit local resource limits.
func (p *Presign) VerifySignMaterialWithLimits(limits Limits) error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if err := validateSignVerifyShares(p.state.signers, p.state.verifyShares, limits); err != nil {
		return err
	}
	return nil
}

// Destroy marks the presign consumed and clears its local secret shares.
func (p *Presign) Destroy() {
	if p == nil || p.state == nil {
		return
	}
	if p.state.consumed != nil {
		p.state.consumed.Store(true)
	}
	if p.state.attempt != nil {
		p.state.attempt.discard()
	}
	if p.state.kShare != nil {
		p.state.kShare.Destroy()
	}
	if p.state.chiShare != nil {
		p.state.chiShare.Destroy()
	}
	if p.state.delta != nil {
		p.state.delta.Destroy()
	}
	if p.state.derivation != nil {
		p.state.derivation.Destroy()
	}
	clear(p.state.planHash)
}

// PresignSession tracks the CGGMP21-style offline presign exchange.
type PresignSession struct {
	mu sync.Mutex

	key            *KeyShare             // Caller-owned long-lived key share used to start presign.
	sessionID      tss.SessionID         // Presign session ID bound into envelopes and planHash.
	config         tss.ThresholdConfig   // Local threshold runtime view for signer membership and transport.
	log            tss.Logger            // Optional protocol logger.
	limits         Limits                // Local fail-closed resource policy.
	securityParams SecurityParams        // Cryptographic profile inherited from the key share.
	signers        tss.PartySet          // Canonical signer set participating in this presign.
	context        PresignContext        // Normalized context bound to the resulting presign.
	contextHash    []byte                // Hash of context; echoed through presign/sign validation.
	derivation     *tss.DerivationResult // Resolved child key/path; destroyed if the session aborts.
	planHash       []byte                // Digest every presign round payload must echo.
	paillier       *pai.PrivateKey       // Local Paillier private key used for MtA decryption.
	guard          *tss.EnvelopeGuard    // Transport replay, identity, and policy guard.

	kShare    *secret.Scalar // Local nonce share k, secret-bearing until presign completes or aborts.
	gamma     *secret.Scalar // Local gamma nonce share, secret-bearing until presign completes or aborts.
	xBar      *secret.Scalar // Local additive signing share adjusted for HD derivation.
	gammaComm []byte         // Public commitment to gamma used in round-1 proof binding.
	xBarComm  []byte         // Public commitment to xBar used in round-3 proof binding.

	partyIndex map[tss.PartyID]int // Index into parties; initialized once at StartPresign.
	parties    []presignPartyState // Ordered by canonical signer set.

	startOpening *mta.StartOpening // Local MtA opening material; secret-bearing until round 2 completes.

	round2Sent      bool     // Whether this party already emitted round-2 MtA responses.
	round3Sent      bool     // Whether this party already emitted round-3 verification material.
	completed       bool     // Terminal success flag; presign is available once true.
	aborted         bool     // Terminal failure/destruction flag.
	presign         *Presign // Completed local presign record, destroyed if the session aborts.
	presignReturned bool     // Tracks whether the completed presign has been handed to the caller.
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
	payload     presignRound2Payload
	havePayload bool
}

type presignRound3State struct {
	delta           *secret.Scalar
	verifyShare     signVerifyShare
	haveDelta       bool
	haveVerifyShare bool
}

type presignMTAState struct {
	alphaDelta *secret.Scalar
	betaDelta  *secret.Scalar
	alphaSigma *secret.Scalar
	betaSigma  *secret.Scalar
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
	if s.presign != nil {
		s.presign.Destroy()
		s.presign = nil
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
	clear(r.payload.Gamma)
	clear(r.payload.EncK)
	secret.ClearBigInt(r.payload.PaillierPublicKey.N)
	secret.ClearBigInt(r.payload.PaillierPublicKey.G)
	secret.ClearBigInt(r.payload.PaillierPublicKey.NSquared)
	clear(r.proof.PublicRound1Hash)
	clearEncProof(&r.proof.EncKProof)
	*r = presignRound1State{}
}

func (r *presignRound2State) destroy() {
	if r == nil {
		return
	}
	clear(r.payload.Delta.Ciphertext)
	clearAffGProof(&r.payload.Delta.Proof)
	clear(r.payload.Sigma.Ciphertext)
	clearAffGProof(&r.payload.Sigma.Proof)
	clear(r.payload.Round1Echo)
	*r = presignRound2State{}
}

func (r *presignRound3State) destroy() {
	if r == nil {
		return
	}
	if r.delta != nil {
		r.delta.Destroy()
	}
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
	*m = presignMTAState{}
}

// SignSession tracks the online threshold ECDSA signing exchange.
type SignSession struct {
	mu sync.Mutex

	key            *KeyShare                   // Caller-owned key share used to validate local ownership.
	presign        *Presign                    // One-use presign handle bound by the durable attempt store.
	sessionID      tss.SessionID               // Online signing session ID for partial-signature envelopes.
	guard          *tss.EnvelopeGuard          // Transport replay, identity, and policy guard.
	log            tss.Logger                  // Optional protocol logger.
	limits         Limits                      // Local fail-closed resource policy.
	digest         []byte                      // Context-bound message digest signed by ECDSA.
	planHash       []byte                      // Digest every sign partial must echo.
	publicKey      []byte                      // Verification key used for final ECDSA self-checking.
	partials       map[tss.PartyID]secp.Scalar // Validated ECDSA partial scalars keyed by signer.
	completed      bool                        // Terminal success flag; signature is available once true.
	aborted        bool                        // Terminal failure/destruction flag.
	signature      *Signature                  // Final aggregated signature, cleared by Destroy.
	attempt        SignAttemptRecord           // Durable one-use attempt/outbox record.
	coordinator    *signAttemptCoordinator     // Durable one-use attempt and outbox coordinator.
	coordinatorCtx context.Context             // Detached context used for handler-triggered durable effects.
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
}

type presignRound1Payload struct {
	Gamma             []byte        `json:"gamma" wire:"1,bytes,max_bytes=point"`
	EncK              []byte        `json:"enc_k" wire:"2,bytes,max_bytes=paillier_ciphertext"`
	PaillierPublicKey pai.PublicKey `json:"paillier_public_key" wire:"3,nested,max_bytes=paillier_public_key"`
	PlanHash          []byte        `json:"plan_hash" wire:"4,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound1Payload.
func (presignRound1Payload) WireType() string { return presignRound1PayloadWireType }

// WireVersion returns the wire format version for presignRound1Payload.
func (presignRound1Payload) WireVersion() uint16 { return presignRound1PayloadWireVersion }

type presignRound1ProofPayload struct {
	PublicRound1Hash []byte         `json:"public_round1_hash" wire:"1,bytes,len=32"`
	EncKProof        zkpai.EncProof `json:"enc_k_proof" wire:"2,nested,max_bytes=zk_proof"`
	PlanHash         []byte         `json:"plan_hash" wire:"3,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound1ProofPayload.
func (presignRound1ProofPayload) WireType() string { return presignRound1ProofPayloadWireType }

// WireVersion returns the wire format version for presignRound1ProofPayload.
func (presignRound1ProofPayload) WireVersion() uint16 {
	return presignRound1ProofPayloadWireVersion
}

type presignRound2Payload struct {
	Delta      mta.ResponseMessage `json:"delta" wire:"1,nested,max_bytes=mta_response"`
	Sigma      mta.ResponseMessage `json:"sigma" wire:"2,nested,max_bytes=mta_response"`
	Round1Echo []byte              `json:"round1_echo" wire:"3,bytes,len=32"`
	PlanHash   []byte              `json:"plan_hash" wire:"4,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound2Payload.
func (presignRound2Payload) WireType() string { return presignRound2PayloadWireType }

// WireVersion returns the wire format version for presignRound2Payload.
func (presignRound2Payload) WireVersion() uint16 { return presignRound2PayloadWireVersion }

type presignRound3Payload struct {
	Delta    *secret.Scalar  `json:"-" wire:"1,custom,len=32"`
	KPoint   *secp.Point     `json:"k_point" wire:"2,custom,len=33"`
	ChiPoint *secp.Point     `json:"chi_point" wire:"3,custom,len=33"`
	Proof    *signprep.Proof `json:"proof" wire:"4,custom,max_bytes=signprep_proof"`
	PlanHash []byte          `json:"plan_hash" wire:"5,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for presignRound3Payload.
func (presignRound3Payload) WireType() string { return presignRound3PayloadWireType }

// WireVersion returns the wire format version for presignRound3Payload.
func (presignRound3Payload) WireVersion() uint16 { return presignRound3PayloadWireVersion }

type signPartialPayload struct {
	S                   *secret.Scalar `json:"-" wire:"1,custom,len=32"`
	PresignTranscript   []byte         `json:"presign_transcript" wire:"2,bytes,len=32"`
	PresignContext      []byte         `json:"presign_context" wire:"3,bytes,len=32"`
	DigestHash          []byte         `json:"digest_hash" wire:"4,bytes,len=32"`
	PartialEquationHash []byte         `json:"partial_equation_hash" wire:"5,bytes,len=32"`
	PlanHash            []byte         `json:"plan_hash" wire:"6,bytes,len=32"`
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
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.signers, s.key.state.party)
}

// HandlePresignMessage validates and applies one presign envelope.
// It dispatches to per-round transitions that decode, validate, verify,
// prepare, commit, and only then return effects.
func (s *PresignSession) HandlePresignMessage(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
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
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("duplicate presign round1"))
		}
		tx, err := s.buildAcceptPresignRound1PayloadTx(base)
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

	case payloadPresignRound1Proof:
		if base.Round != presignStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round1 proof payload in wrong round"))
		}
		if base.From == s.key.state.party {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("self presign round1 proof is not expected"))
		}
		if st.round1.haveProof {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("duplicate presign round1 proof"))
		}
		tx, err := s.buildAcceptPresignRound1ProofTx(base)
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

	case payloadPresignRound2:
		if base.Round != presignRound2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round2 payload in wrong round"))
		}
		if st.round2.havePayload {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("duplicate presign round2"))
		}
		tx, err := s.buildAcceptPresignRound2Tx(base)
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

	case payloadPresignRound3:
		if base.Round != presignRound3 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("round3 payload in wrong round"))
		}
		if st.round3.haveDelta {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("duplicate delta share"))
		}
		tx, err := s.buildAcceptPresignRound3Tx(base)
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

	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
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
