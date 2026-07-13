package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/signprep"
)

const (
	presignTranscriptHashLabel = "cggmp21-secp256k1-presign-transcript-v1"
	presignContextHashLabel    = "cggmp21-secp256k1-presign-context-v1"
	presignRound1EchoLabel     = "cggmp21-secp256k1-presign-round1-echo-v1"
	presignRound1PublicLabel   = "cggmp21-secp256k1-presign-round1-public-v1"
	signMessageDigestLabel     = "cggmp21-secp256k1-sign-message-v1"
	mtaResponseEvidenceLabel   = "cggmp21-secp256k1-mta-response-evidence-v1"

	// DefaultSignAttemptStoreTimeout bounds durable sign-attempt store calls
	// after local validation has completed.
	DefaultSignAttemptStoreTimeout = 5 * time.Second
)

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
// signing. CommitSignAttempt must atomically bind one secret-tainted presign
// content ID to one immutable intent and its exact canonical outbound envelope.
//
// CommitSignAttempt accepts an incomplete candidate, creates the attempt, or
// returns the existing exact attempt. ErrSignAttemptConflict, ErrSignAttemptBurned,
// and ErrSignAttemptNonDeterminism are consumed outcomes. Any other commit error
// has an unknown outcome: callers must retain the local binding and retry or
// resume only the same intent. LoadSignAttempt is for ResumeSign and inspection;
// it is not part of StartSign's linearization path.
// CompleteSignAttempt is idempotent and must make the final signature durable
// before returning success. Presign content IDs are secret-tainted commitments;
// stores must derive opaque store-local keys before using them in paths,
// indexes, logs, metrics, or plaintext metadata.
type SignAttemptStore interface {
	CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error)
	LoadSignAttempt(ctx context.Context, presignContentID []byte) (SignAttemptRecord, error)
	UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error)
	CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error)
	BurnPresign(ctx context.Context, burn SignAttemptBurn) error
}

// SignRequest is the context-bound message to verify against a signature.
// Message is hashed with the signing context before ECDSA verification.
type SignRequest struct {
	Context tss.SigningContext `json:"context"`
	Message []byte             `json:"message"`
}

// Clone returns a caller-owned copy of the sign request.
func (r SignRequest) Clone() SignRequest {
	return SignRequest{
		Context: r.Context.Clone(),
		Message: slices.Clone(r.Message),
	}
}

// SignIntent is the shared online signing intent all CGGMP21 signers must
// accept before producing a partial signature.
type SignIntent struct {
	SessionID tss.SessionID
	Context   tss.SigningContext
	Message   []byte
	Signers   tss.PartySet
}

// Clone returns a caller-owned copy of the sign intent.
func (i SignIntent) Clone() SignIntent {
	return SignIntent{
		SessionID: i.SessionID,
		Context:   i.Context.Clone(),
		Message:   slices.Clone(i.Message),
		Signers:   i.Signers.Clone(),
	}
}

// Request returns the context-bound request represented by the intent.
func (i SignIntent) Request() SignRequest {
	return SignRequest{
		Context: i.Context.Clone(),
		Message: slices.Clone(i.Message),
	}
}

// SignRuntime contains this process's local execution dependencies for
// CGGMP21 online signing. These values are not shared intent and are not part
// of the sign plan digest.
type SignRuntime struct {
	Local               tss.LocalConfig
	Guard               *tss.EnvelopeGuard
	Presign             *Presign
	AttemptStore        SignAttemptStore
	DurableStoreTimeout time.Duration
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
	Party                     tss.PartyID                       `wire:"1,u32"`                           // Local owner of this presign share.
	Threshold                 int                               `wire:"2,u32"`                           // Number of signer partials required to complete ECDSA signing.
	Signers                   tss.PartySet                      `wire:"3,u32list,max_items=signers"`     // Canonical signer set authorized for this presign.
	R                         *secp.Point                       `wire:"4,custom,len=33"`                 // Aggregate nonce point R.
	LittleR                   secp.Scalar                       `wire:"5,custom,len=32"`                 // ECDSA r scalar derived from R.
	KShare                    *secret.Scalar                    `wire:"6,custom,len=32"`                 // Local nonce-share secret used once during online signing.
	ChiShare                  *secret.Scalar                    `wire:"7,custom,len=32"`                 // Local chi-share secret used once during online signing.
	DeltaAggregate            *secret.Scalar                    `wire:"8,custom,len=32"`                 // Aggregate delta reconstructed from every signer's round-3 share.
	TranscriptHash            []byte                            `wire:"9,bytes,len=32"`                  // Cross-party presign transcript hash.
	Context                   tss.SigningContext                `wire:"10,nested"`                       // Normalized context bound before online signing.
	ContextHash               []byte                            `wire:"11,bytes,len=32"`                 // Hash of context, used to reject cross-context reuse.
	Consumed                  AtomicBoolWire                    `wire:"12,custom,len=1"`                 // Shared in-process one-use marker across shallow copies.
	PublicKey                 *secp.Point                       `wire:"13,custom,len=33"`                // Parent group public key before request-time HD derivation.
	KeygenTranscriptHash      []byte                            `wire:"14,bytes,len=32"`                 // Transcript hash of the keygen that produced PublicKey.
	PartiesHash               []byte                            `wire:"15,bytes,len=32"`                 // Hash of the full key-share participant set.
	VerifyShares              []signVerifyShare                 `wire:"16,recordlist,max_items=signers"` // Per-signer public verification material for online partials.
	PlanHash                  []byte                            `wire:"17,bytes,len=32"`                 // Digest of the presign lifecycle plan accepted by all signers.
	SecurityParams            SecurityParams                    `wire:"18,record"`                       // Cryptographic profile inherited from the key share.
	Derivation                *tss.DerivationResult             `wire:"19,record"`                       // Resolved child key/path; ChildPublicKey is the verification key.
	Verification              presignVerificationContext        `wire:"20,record"`                       // Persisted public context required to replay signprep verification.
	IdentificationTranscripts []presignIdentificationTranscript `wire:"21,recordlist,max_items=signers"` // Public pairwise MtA transcript for conditional identification.
	SigmaOpeningRecords       []presignSigmaOpeningRecord       `wire:"22,recordlist,max_items=signers"` // Encrypted-storage-only sigma identification witnesses.
	sigmaOpenings             []presignSigmaOpening             `wire:"-"`                               // One-attempt online identification witnesses.
	attempt                   *presignAttemptBinding            `wire:"-"`                               // Durable attempt binding/outbox state for one-use signing.
}

type presignSigmaOpening struct {
	Peer     tss.PartyID
	Response mta.ResponseMessage
	Opening  *mta.ResponseOpening
}

type presignSigmaOpeningRecord struct {
	Peer     tss.PartyID         `wire:"1,u32"`
	Response mta.ResponseMessage `wire:"2,nested,max_bytes=mta_response"`
	Opening  []byte              `wire:"3,bytes,max_bytes=mta_response"`
}

func buildPresignSigmaOpeningRecords(openings []presignSigmaOpening) ([]presignSigmaOpeningRecord, error) {
	records := make([]presignSigmaOpeningRecord, 0, len(openings))
	for i := range openings {
		encoded, err := openings[i].Opening.MarshalPrivateBinary()
		if err != nil {
			destroyPresignSigmaOpeningRecords(records)
			return nil, err
		}
		records = append(records, presignSigmaOpeningRecord{
			Peer: openings[i].Peer, Response: openings[i].Response.Clone(), Opening: encoded,
		})
	}
	return records, nil
}

func destroyPresignSigmaOpeningRecords(records []presignSigmaOpeningRecord) {
	for i := range records {
		records[i].Response.Destroy()
		clear(records[i].Opening)
		records[i] = presignSigmaOpeningRecord{}
	}
}

func validatePresignSigmaOpeningRecords(records []presignSigmaOpeningRecord, signers tss.PartySet) error {
	if len(records) != len(signers)-1 {
		return errors.New("presign sigma opening record count mismatch")
	}
	for i := range records {
		if records[i].Peer == 0 || records[i].Peer == tss.BroadcastPartyId || !tss.ContainsParty(signers, records[i].Peer) {
			return errors.New("invalid presign sigma opening peer")
		}
		if i > 0 && records[i-1].Peer >= records[i].Peer {
			return errors.New("non-canonical presign sigma opening order")
		}
		if err := records[i].Response.Validate(); err != nil {
			return fmt.Errorf("invalid presign sigma response: %w", err)
		}
		var opening mta.ResponseOpening
		if err := opening.UnmarshalPrivateBinary(records[i].Opening); err != nil {
			return fmt.Errorf("invalid private presign sigma opening: %w", err)
		}
		opening.Destroy()
	}
	return nil
}

// activatePresignSigmaOpeningRecords creates short-lived or attempt-owned
// witness handles after the persisted public/private bindings have been
// validated. Each resumed session owns an independent copy so destroying one
// idempotent session cannot invalidate another session for the same exact
// attempt.
func activatePresignSigmaOpeningRecords(presign *Presign) ([]presignSigmaOpening, error) {
	if presign == nil || presign.state == nil {
		return nil, errors.New("nil presign")
	}
	records := presign.state.SigmaOpeningRecords
	if err := validatePresignSigmaOpeningRecords(records, presign.state.Signers); err != nil {
		return nil, err
	}
	transcriptValue, ok := presignIdentificationTranscriptFor(presign, presign.state.Party)
	if !ok {
		return nil, errors.New("missing local sigma identification transcript")
	}
	localEntry, ok := presignVerificationEntryFor(presign, presign.state.Party)
	if !ok {
		return nil, errors.New("missing local sigma verification entry")
	}
	localXBar, err := secp.PointBytes(localEntry.XBarPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid local sigma XBar commitment: %w", err)
	}
	openings := make([]presignSigmaOpening, 0, len(records))
	for i := range records {
		contribution, ok := mtaContributionFor(transcriptValue.Contributions, records[i].Peer)
		if !ok || !sameSigmaResponse(records[i].Response, contribution.Outbound) {
			destroyPresignSigmaOpenings(openings)
			return nil, fmt.Errorf("presign sigma opening response mismatch for peer %d", records[i].Peer)
		}
		opening := new(mta.ResponseOpening)
		if err := opening.UnmarshalPrivateBinary(records[i].Opening); err != nil {
			destroyPresignSigmaOpenings(openings)
			return nil, fmt.Errorf("activate private presign sigma opening: %w", err)
		}
		peerEntry, ok := presignVerificationEntryFor(presign, records[i].Peer)
		if !ok {
			opening.Destroy()
			destroyPresignSigmaOpenings(openings)
			return nil, fmt.Errorf("missing sigma verification entry for peer %d", records[i].Peer)
		}
		if err := opening.Verify(
			presign.state.SecurityParams,
			mta.StartMessage{Ciphertext: peerEntry.EncK},
			records[i].Response,
			peerEntry.KPoint,
			localXBar,
			peerEntry.PaillierPublicKey,
			localEntry.PaillierPublicKey,
		); err != nil {
			opening.Destroy()
			destroyPresignSigmaOpenings(openings)
			return nil, fmt.Errorf("invalid presign sigma opening for peer %d: %w", records[i].Peer, err)
		}
		openings = append(openings, presignSigmaOpening{
			Peer: records[i].Peer, Response: records[i].Response.Clone(), Opening: opening,
		})
	}
	return openings, nil
}

// verifyPresignSigmaOpeningRecords validates the exact local witness set and
// its public response bindings without retaining reusable opening handles.
func verifyPresignSigmaOpeningRecords(presign *Presign) error {
	openings, err := activatePresignSigmaOpeningRecords(presign)
	if err != nil {
		return err
	}
	destroyPresignSigmaOpenings(openings)
	return nil
}

type presignIdentificationTranscript struct {
	Party         tss.PartyID              `wire:"1,u32"`
	Contributions []presignMTAContribution `wire:"2,recordlist,max_items=signers"`
}

func validatePresignIdentificationTranscripts(transcripts []presignIdentificationTranscript, signers tss.PartySet) error {
	if len(transcripts) != len(signers) {
		return fmt.Errorf("presign identification transcript count %d != signers %d", len(transcripts), len(signers))
	}
	for i := range transcripts {
		value := &transcripts[i]
		if value.Party != signers[i] {
			return fmt.Errorf("presign identification party %d out of canonical signer order at index %d", value.Party, i)
		}
		if len(value.Contributions) != len(signers)-1 {
			return fmt.Errorf("presign identification contribution count for party %d is %d, want %d", value.Party, len(value.Contributions), len(signers)-1)
		}
		index := 0
		for _, peer := range signers {
			if peer == value.Party {
				continue
			}
			contribution := &value.Contributions[index]
			index++
			if contribution.Peer != peer {
				return fmt.Errorf("presign identification peer %d for party %d is out of canonical signer order", contribution.Peer, value.Party)
			}
			for _, response := range []struct {
				name  string
				value mta.ResponseMessage
			}{
				{name: "inbound sigma", value: contribution.Inbound},
				{name: "outbound sigma", value: contribution.Outbound},
				{name: "inbound delta", value: contribution.InboundDelta},
				{name: "outbound delta", value: contribution.OutboundDelta},
			} {
				if err := response.value.Validate(); err != nil {
					return fmt.Errorf("invalid %s identification response for party %d and peer %d: %w", response.name, value.Party, peer, err)
				}
			}
		}
	}
	return nil
}

func (t *presignIdentificationTranscript) destroy() {
	if t == nil {
		return
	}
	destroyMTAContributions(t.Contributions)
	*t = presignIdentificationTranscript{}
}

func (o *presignSigmaOpening) destroy() {
	if o == nil {
		return
	}
	o.Response.Destroy()
	if o.Opening != nil {
		o.Opening.Destroy()
	}
	*o = presignSigmaOpening{}
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
	rBytes, err := secp.PointBytes(p.state.R)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	publicKeyBytes, err := secp.PointBytes(p.state.PublicKey)
	if err != nil {
		return PresignPublicMetadata{}, false
	}
	return PresignPublicMetadata{
		SecurityParams:       p.state.SecurityParams,
		Party:                p.state.Party,
		Threshold:            p.state.Threshold,
		Signers:              p.state.Signers.Clone(),
		R:                    rBytes,
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

// MarshalBinary encodes a consumed snapshot of the presign record using the
// object-level wire codec.
func (p *Presign) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a consumed snapshot of the presign using
// explicit local limits.
func (p *Presign) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return p.marshalWireMessageWithLimits(limits)
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
	if p == nil || p.state == nil || p.state.Derivation == nil {
		return nil
	}
	return p.state.Derivation.VerificationKeyBytes()
}

// Validate checks local presign structure and scalar/point encodings.
func (p *Presign) Validate() error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if !isProductionSecurityParams(p.state.SecurityParams) {
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
	if _, err := secp.PointBytes(p.state.R); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	if p.state.LittleR.IsZero() {
		return errors.New("invalid little r: zero")
	}
	if _, err := secpScalarFromSecret(p.state.KShare); err != nil {
		return fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secpScalarFromSecret(p.state.ChiShare); err != nil {
		return fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secpScalarFromSecret(p.state.DeltaAggregate); err != nil {
		return fmt.Errorf("invalid delta: %w", err)
	}
	if len(p.state.TranscriptHash) != sha256.Size {
		return errors.New("invalid presign transcript hash")
	}
	if err := validatePresignContext(p.state.Context); err != nil {
		return err
	}
	if len(p.state.ContextHash) != sha256.Size {
		return errors.New("invalid presign context hash")
	}
	if err := validateDerivationResult(p.state.Derivation, tss.DerivationSchemeBIP32Secp256k1); err != nil {
		return fmt.Errorf("invalid presign derivation: %w", err)
	}
	if len(p.state.Derivation.AdditiveShift) > 0 {
		if _, err := secp.ScalarFromBytesAllowZero(p.state.Derivation.AdditiveShift); err != nil {
			return fmt.Errorf("invalid additive shift: %w", err)
		}
	}
	if len(p.state.PlanHash) != sha256.Size {
		return errors.New("invalid presign plan hash")
	}
	if _, err := secp.PointBytes(p.state.PublicKey); err != nil {
		return fmt.Errorf("invalid presign public key binding: %w", err)
	}
	if _, err := secp.PointFromBytes(p.state.Derivation.ChildPublicKey); err != nil {
		return fmt.Errorf("invalid presign verification key binding: %w", err)
	}
	if err := validateSecp256k1DerivationBinding(p.state.PublicKey, p.state.Derivation); err != nil {
		return fmt.Errorf("invalid presign verification key binding: %w", err)
	}
	if len(p.state.KeygenTranscriptHash) != sha256.Size {
		return errors.New("invalid presign keygen transcript hash binding")
	}
	if len(p.state.PartiesHash) != sha256.Size {
		return errors.New("invalid presign party-set hash binding")
	}
	if !bytes.Equal(presignContextHash(p.state.Context), p.state.ContextHash) {
		return errors.New("presign context hash mismatch")
	}
	if err := validateSignVerifyShares(p.state.Signers, p.state.VerifyShares, limits); err != nil {
		return fmt.Errorf("invalid presign verify shares: %w", err)
	}
	if err := validatePresignVerificationContext(p.state.Signers, p.state.Verification, limits); err != nil {
		return fmt.Errorf("invalid presign verification context: %w", err)
	}
	if err := validatePresignIdentificationTranscripts(p.state.IdentificationTranscripts, p.state.Signers); err != nil {
		return err
	}
	if err := validatePresignSigmaOpeningRecords(p.state.SigmaOpeningRecords, p.state.Signers); err != nil {
		return err
	}
	return nil
}

// VerifySignMaterial performs complete cryptographic self-verification of the
// persisted presign material.
func (p *Presign) VerifySignMaterial() error {
	return p.VerifySignMaterialWithLimits(DefaultLimits())
}

// VerifySignMaterialWithLimits is an alias for
// [Presign.VerifyCryptographicMaterialWithLimits].
func (p *Presign) VerifySignMaterialWithLimits(limits Limits) error {
	return p.VerifyCryptographicMaterialWithLimits(limits)
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
	if p.state.DeltaAggregate != nil {
		p.state.DeltaAggregate.Destroy()
	}
	for i := range p.state.VerifyShares {
		p.state.VerifyShares[i].destroy()
	}
	p.state.VerifyShares = nil
	p.state.Verification.destroy()
	for i := range p.state.sigmaOpenings {
		p.state.sigmaOpenings[i].destroy()
	}
	p.state.sigmaOpenings = nil
	destroyPresignSigmaOpeningRecords(p.state.SigmaOpeningRecords)
	p.state.SigmaOpeningRecords = nil
	for i := range p.state.IdentificationTranscripts {
		p.state.IdentificationTranscripts[i].destroy()
	}
	p.state.IdentificationTranscripts = nil
	if p.state.Derivation != nil {
		p.state.Derivation.Destroy()
	}
	clear(p.state.PlanHash)
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
	context        tss.SigningContext    // Normalized context bound to the resulting presign.
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
	gammaOpening *mta.StartOpening // Local encrypted gamma opening retained for identification.

	round2Sent             bool     // Whether this party already emitted round-2 MtA responses.
	round3Sent             bool     // Whether this party already emitted round-3 verification material.
	completed              bool     // Terminal success flag; presign is available once true.
	identifying            bool     // Conditional identifiable-abort round is active.
	aborted                bool     // Terminal failure/destruction flag.
	presign                *Presign // Completed local presign record, destroyed if the session aborts.
	presignReturned        bool     // Tracks whether the completed presign has been handed to the caller.
	identificationAlert    []byte
	identificationPayloads map[tss.PartyID]presignIdentificationPayload
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
	delta           *secret.Scalar
	verifyShare     signVerifyShare
	haveDelta       bool
	haveVerifyShare bool
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
	if s.gammaOpening != nil {
		s.gammaOpening.Destroy()
		s.gammaOpening = nil
	}
	if s.presign != nil {
		s.presign.Destroy()
		s.presign = nil
	}
	clear(s.identificationAlert)
	for party, payload := range s.identificationPayloads {
		payload.destroy()
		delete(s.identificationPayloads, party)
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
	clear(r.payload.EncGamma)
	clear(r.payload.KPoint)
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
	clear(r.payload.Delta.Ciphertext)
	r.payload.Delta.Proof.Destroy()
	clear(r.payload.Sigma.Ciphertext)
	r.payload.Sigma.Proof.Destroy()
	clear(r.payload.Round1Echo)
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
	r.verifyShare.destroy()
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

	key                    *KeyShare                   // Caller-owned key share used to validate local ownership.
	presign                *Presign                    // One-use presign handle bound by the durable attempt store.
	sessionID              tss.SessionID               // Online signing session ID for partial-signature envelopes.
	guard                  *tss.EnvelopeGuard          // Transport replay, identity, and policy guard.
	log                    tss.Logger                  // Optional protocol logger.
	limits                 Limits                      // Local fail-closed resource policy.
	digest                 []byte                      // Context-bound message digest signed by ECDSA.
	planHash               []byte                      // Digest every sign partial must echo.
	publicKey              []byte                      // Verification key used for final ECDSA self-checking.
	partials               map[tss.PartyID]secp.Scalar // Validated ECDSA partial scalars keyed by signer.
	partialEnvelopes       map[tss.PartyID]tss.Envelope
	completed              bool // Terminal success flag; signature is available once true.
	identifying            bool // Conditional signing identification round is active.
	identificationAlert    []byte
	identificationPayloads map[tss.PartyID]signIdentificationPayload
	sigmaOpenings          []presignSigmaOpening   // Attempt-owned online identification witnesses.
	aborted                bool                    // Terminal failure/destruction flag.
	signature              *Signature              // Final aggregated signature, cleared by Destroy.
	attempt                SignAttemptRecord       // Durable one-use attempt/outbox record.
	coordinator            *signAttemptCoordinator // Durable one-use attempt and outbox coordinator.
	coordinatorCtx         context.Context         // Detached context used for handler-triggered durable effects.
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
	clear(s.identificationAlert)
	for id, payload := range s.identificationPayloads {
		payload.destroy()
		delete(s.identificationPayloads, id)
	}
	s.destroyOnlineIdentificationOpenings()
}

func (s *SignSession) destroyOnlineIdentificationOpenings() {
	if s == nil {
		return
	}
	for i := range s.sigmaOpenings {
		s.sigmaOpenings[i].destroy()
	}
	s.sigmaOpenings = nil
}

type presignRound1Payload struct {
	Gamma             []byte         `json:"gamma" wire:"1,bytes,max_bytes=point"`
	EncK              []byte         `json:"enc_k" wire:"2,bytes,max_bytes=paillier_ciphertext"`
	PaillierPublicKey *pai.PublicKey `json:"paillier_public_key" wire:"3,nested,max_bytes=paillier_public_key"`
	PlanHash          []byte         `json:"plan_hash" wire:"4,bytes,len=32"`
	KPoint            []byte         `json:"k_point" wire:"5,bytes,len=33"`
	EncGamma          []byte         `json:"enc_gamma" wire:"6,bytes,max_bytes=paillier_ciphertext"`
}

// WireType returns the canonical wire type identifier for presignRound1Payload.
func (presignRound1Payload) WireType() string { return presignRound1PayloadWireType }

// WireVersion returns the wire format version for presignRound1Payload.
func (presignRound1Payload) WireVersion() uint16 { return presignRound1PayloadWireVersion }

type presignRound1ProofPayload struct {
	PublicRound1Hash []byte             `json:"public_round1_hash" wire:"1,bytes,len=32"`
	EncKProof        zkpai.LogStarProof `json:"enc_k_proof" wire:"2,nested,max_bytes=zk_proof"`
	PlanHash         []byte             `json:"plan_hash" wire:"3,bytes,len=32"`
	EncGammaProof    zkpai.LogStarProof `json:"enc_gamma_proof" wire:"4,nested,max_bytes=zk_proof"`
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
	Delta             *secret.Scalar            `json:"-" wire:"1,custom,len=32"`
	KPoint            *secp.Point               `json:"k_point" wire:"2,custom,len=33"`
	ChiPoint          *secp.Point               `json:"chi_point" wire:"3,custom,len=33"`
	Proof             *signprep.Proof           `json:"proof" wire:"4,custom,max_bytes=signprep_proof"`
	PlanHash          []byte                    `json:"plan_hash" wire:"5,bytes,len=32"`
	Round2Commitments []presignRound2Commitment `json:"round2_commitments" wire:"6,recordlist,max_items=signers"`
	MTAContributions  []presignMTAContribution  `json:"mta_contributions" wire:"7,recordlist,max_items=signers"`
}

type presignRound2Commitment struct {
	Recipient tss.PartyID `wire:"1,u32"`
	Hash      []byte      `wire:"2,bytes,len=32"`
}

type presignMTAContribution struct {
	Peer             tss.PartyID         `wire:"1,u32"`
	Inbound          mta.ResponseMessage `wire:"2,nested,max_bytes=mta_response"`
	Outbound         mta.ResponseMessage `wire:"3,nested,max_bytes=mta_response"`
	InboundDelta     mta.ResponseMessage `wire:"4,nested,max_bytes=mta_response"`
	OutboundDelta    mta.ResponseMessage `wire:"5,nested,max_bytes=mta_response"`
	InboundEnvelope  []byte              `wire:"6,bytes,max_bytes=envelope"`
	OutboundEnvelope []byte              `wire:"7,bytes,max_bytes=envelope"`
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
	if base.PayloadType == payloadPresignIdentification {
		if err := validateIdentificationPayloadSize(base); err != nil {
			return nil, err
		}
	}
	defer func() {
		err = bindInboundAuthenticationEvidence(err, env)
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if base.PayloadType == payloadPresignIdentification && !s.identifying {
		if err := tss.ValidateInboundWithoutReplay(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.signers, s.key.state.Party); err != nil {
			return nil, err
		}
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("presign identification is not active"))
	}
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
		if st.round3.haveDelta {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate delta share"))
		}
		if err := s.validatePresignInboundReadiness(base); err != nil {
			return nil, err
		}
		tx, err := s.buildAcceptPresignRound3Tx(base)
		if err != nil {
			return nil, err
		}
		return applyPresignTransition(s, env, tx)

	case payloadPresignIdentification:
		if base.Round != presignIdentificationRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("presign identification payload in wrong round"))
		}
		if _, exists := s.identificationPayloads[base.From]; exists {
			return s.rejectAcceptedPresignDuplicate(env, errors.New("duplicate presign identification payload"))
		}
		tx, err := s.buildAcceptPresignIdentificationTx(base)
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
	if !s.completed || s.identifying {
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
