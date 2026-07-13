package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/islishude/tss"
)

const (
	// EpochIDSize is the fixed size of an authorization epoch identifier.
	EpochIDSize = sha256.Size

	maxLifecycleIdentifierBytes = 256
	maxLifecycleReasonBytes     = 256
	maxLifecycleBlobBytes       = 16 << 20
)

// EpochID identifies one authorization epoch. The all-zero value is invalid.
type EpochID [EpochIDSize]byte

// NewEpochID validates and copies a fixed-width authorization epoch identifier.
func NewEpochID(raw []byte) (EpochID, error) {
	var id EpochID
	if len(raw) != EpochIDSize {
		return id, fmt.Errorf("%w: epoch id must be %d bytes", ErrInvalidLifecycleRecord, EpochIDSize)
	}
	copy(id[:], raw)
	if !id.Valid() {
		return EpochID{}, fmt.Errorf("%w: zero epoch id", ErrInvalidLifecycleRecord)
	}
	return id, nil
}

// Valid reports whether id is non-zero.
func (id EpochID) Valid() bool {
	return id != EpochID{}
}

// Bytes returns a caller-owned fixed-width encoding of id.
func (id EpochID) Bytes() []byte {
	return slices.Clone(id[:])
}

// GenerationBinding identifies one exact key-share generation and
// authorization epoch.
type GenerationBinding struct {
	KeyID         string
	KeyGeneration KeyGeneration
	EpochID       EpochID
}

// Validate checks that every generation-binding component is present and
// suitable for use as durable metadata.
func (b GenerationBinding) Validate() error {
	if err := validateLifecycleIdentifier(b.KeyID); err != nil {
		return fmt.Errorf("%w: invalid key id", ErrInvalidLifecycleRecord)
	}
	if err := validateLifecycleIdentifier(string(b.KeyGeneration)); err != nil {
		return fmt.Errorf("%w: invalid key generation", ErrInvalidLifecycleRecord)
	}
	if !b.EpochID.Valid() {
		return fmt.Errorf("%w: zero epoch id", ErrInvalidLifecycleRecord)
	}
	return nil
}

// GenerationStatus is the durable lifecycle status of a generation.
type GenerationStatus uint8

const (
	// GenerationCurrent means the generation may acquire new work.
	GenerationCurrent GenerationStatus = iota + 1
	// GenerationRetired means the generation can no longer acquire work.
	GenerationRetired
)

// GenerationRecord is an opaque stored key-share generation. Blob can contain
// secret material and must be encrypted by production stores.
type GenerationRecord struct {
	Binding  GenerationBinding
	Blob     []byte
	Metadata []byte
	Status   GenerationStatus
}

const generationRecordRedacted = "<tssrun.GenerationRecord:redacted>"

// Clone returns an independent copy of the generation record.
func (r GenerationRecord) Clone() GenerationRecord {
	r.Blob = bytes.Clone(r.Blob)
	r.Metadata = bytes.Clone(r.Metadata)
	return r
}

// String returns a redacted representation.
func (r GenerationRecord) String() string { return generationRecordRedacted }

// GoString returns a redacted representation.
func (r GenerationRecord) GoString() string { return generationRecordRedacted }

// Format writes a redacted representation for every formatting verb.
func (r GenerationRecord) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, generationRecordRedacted)
}

// RunLeaseState is the durable state of a generation-bound run lease.
type RunLeaseState uint8

const (
	// RunLeaseActive means the run may still use its bound generation.
	RunLeaseActive RunLeaseState = iota + 1
	// RunLeaseCompleted means the run terminated successfully.
	RunLeaseCompleted
	// RunLeaseAborted means the run terminated without a usable result.
	RunLeaseAborted
)

// RunLease is a fencing token for one protocol session and exact generation.
// Callers must present the complete value when finishing the lease.
type RunLease struct {
	Token     uint64
	Binding   GenerationBinding
	Kind      RunKind
	SessionID tss.SessionID
	State     RunLeaseState
}

// Clone returns an independent copy of the run lease.
func (l RunLease) Clone() RunLease { return l }

// RunLeaseOutcome is a terminal outcome accepted by FinishRunLease.
type RunLeaseOutcome uint8

const (
	// LeaseCompleted records successful terminal completion.
	LeaseCompleted RunLeaseOutcome = iota + 1
	// LeaseAborted records terminal abort.
	LeaseAborted
)

// RefreshDisabledRecord is the durable fail-closed marker installed after a
// protocol-level refresh failure. SessionID identifies the failed refresh run.
type RefreshDisabledRecord struct {
	KeyID     string
	SessionID tss.SessionID
	Reason    string
}

// Clone returns an independent refresh-disabled record.
func (r RefreshDisabledRecord) Clone() RefreshDisabledRecord { return r }

// ReshareReceiverAnchor is the public authoritative source view accepted by a
// new-only reshare receiver that does not hold the source secret generation.
// PlanDigest binds the canonical reshare plan, and SourceEpochDigest binds its
// canonical public source epoch. TargetKeyGeneration is the declared local
// generation that may be installed if the protocol succeeds.
type ReshareReceiverAnchor struct {
	Source              GenerationBinding
	TargetKeyGeneration KeyGeneration
	SessionID           tss.SessionID
	PlanDigest          []byte
	SourceEpochDigest   []byte
}

// Clone returns an independent receiver anchor.
func (a ReshareReceiverAnchor) Clone() ReshareReceiverAnchor {
	a.PlanDigest = bytes.Clone(a.PlanDigest)
	a.SourceEpochDigest = bytes.Clone(a.SourceEpochDigest)
	return a
}

// Validate checks the exact public reshare receiver admission descriptor.
func (a ReshareReceiverAnchor) Validate() error {
	if err := a.Source.Validate(); err != nil {
		return err
	}
	if err := validateLifecycleIdentifier(string(a.TargetKeyGeneration)); err != nil ||
		a.TargetKeyGeneration == a.Source.KeyGeneration || !a.SessionID.Valid() ||
		len(a.PlanDigest) != sha256.Size || len(a.SourceEpochDigest) != sha256.Size {
		return ErrInvalidLifecycleRecord
	}
	var zero [sha256.Size]byte
	if bytes.Equal(a.PlanDigest, zero[:]) || bytes.Equal(a.SourceEpochDigest, zero[:]) {
		return ErrInvalidLifecycleRecord
	}
	return nil
}

// PresignCandidate is a read-only snapshot of one available presign. Blob can
// contain secret material and must not be logged.
type PresignCandidate struct {
	Binding   GenerationBinding
	PresignID string
	Blob      []byte
	Metadata  []byte
}

const presignCandidateRedacted = "<tssrun.PresignCandidate:redacted>"

// Clone returns an independent candidate snapshot.
func (p PresignCandidate) Clone() PresignCandidate {
	p.Blob = bytes.Clone(p.Blob)
	p.Metadata = bytes.Clone(p.Metadata)
	return p
}

// String returns a redacted representation.
func (p PresignCandidate) String() string { return presignCandidateRedacted }

// GoString returns a redacted representation.
func (p PresignCandidate) GoString() string { return presignCandidateRedacted }

// Format writes a redacted representation for every formatting verb.
func (p PresignCandidate) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, presignCandidateRedacted)
}

// SignAttemptIntent is the non-secret immutable identity for one online
// signing attempt. IntentDigest must bind every protocol-level signing input.
type SignAttemptIntent struct {
	AttemptID    string
	SessionID    tss.SessionID
	IntentDigest []byte
}

// Clone returns an independent copy of the intent.
func (i SignAttemptIntent) Clone() SignAttemptIntent {
	i.IntentDigest = bytes.Clone(i.IntentDigest)
	return i
}

// Validate checks the immutable attempt identity.
func (i SignAttemptIntent) Validate() error {
	if err := validateLifecycleIdentifier(i.AttemptID); err != nil {
		return fmt.Errorf("%w: invalid attempt id", ErrInvalidLifecycleRecord)
	}
	if !i.SessionID.Valid() {
		return fmt.Errorf("%w: invalid attempt session id", ErrInvalidLifecycleRecord)
	}
	if len(i.IntentDigest) != sha256.Size {
		return fmt.Errorf("%w: intent digest must be %d bytes", ErrInvalidLifecycleRecord, sha256.Size)
	}
	return nil
}

// AttemptQuery identifies the exact immutable attempt that a caller is
// permitted to recover after an unknown durable outcome.
type AttemptQuery struct {
	Binding      GenerationBinding
	PresignID    string
	AttemptID    string
	IntentDigest []byte
}

// Clone returns an independent copy of the query.
func (q AttemptQuery) Clone() AttemptQuery {
	q.IntentDigest = bytes.Clone(q.IntentDigest)
	return q
}

// Validate checks every attempt-recovery binding.
func (q AttemptQuery) Validate() error {
	if err := q.Binding.Validate(); err != nil {
		return err
	}
	if err := validateLifecycleIdentifier(q.PresignID); err != nil {
		return fmt.Errorf("%w: invalid presign id", ErrInvalidLifecycleRecord)
	}
	if err := validateLifecycleIdentifier(q.AttemptID); err != nil {
		return fmt.Errorf("%w: invalid attempt id", ErrInvalidLifecycleRecord)
	}
	if len(q.IntentDigest) != sha256.Size {
		return fmt.Errorf("%w: intent digest must be %d bytes", ErrInvalidLifecycleRecord, sha256.Size)
	}
	return nil
}

// SignAttemptRecord is the durable claim, public verification context, exact
// outbox, and terminal progress for one generation-bound signing attempt.
// PresignMetadata must contain only public recovery data. A committed attempt
// never retains the available presign's secret blob or normalized tuple.
type SignAttemptRecord struct {
	Binding         GenerationBinding
	PresignID       string
	Intent          SignAttemptIntent
	PresignMetadata []byte
	ExactOutbox     []byte
	OutboxDigest    []byte
	Delivery        []byte
	Completion      []byte
	Delivered       bool
	Completed       bool
	Aborted         bool
	AbortReason     string
}

const signAttemptRecordRedacted = "<tssrun.SignAttemptRecord:redacted>"

// Clone returns an independent copy of the attempt record.
func (r SignAttemptRecord) Clone() SignAttemptRecord {
	r.Intent = r.Intent.Clone()
	r.PresignMetadata = bytes.Clone(r.PresignMetadata)
	r.ExactOutbox = bytes.Clone(r.ExactOutbox)
	r.OutboxDigest = bytes.Clone(r.OutboxDigest)
	r.Delivery = bytes.Clone(r.Delivery)
	r.Completion = bytes.Clone(r.Completion)
	return r
}

// Query returns the non-secret exact-attempt identity for recovery.
func (r SignAttemptRecord) Query() AttemptQuery {
	return AttemptQuery{
		Binding:      r.Binding,
		PresignID:    r.PresignID,
		AttemptID:    r.Intent.AttemptID,
		IntentDigest: bytes.Clone(r.Intent.IntentDigest),
	}
}

// Terminal reports whether no outbound replay or protocol completion work
// remains. Successful attempts become terminal only after both delivery and
// completion are durable.
func (r SignAttemptRecord) Terminal() bool {
	return r.Aborted || (r.Delivered && r.Completed)
}

// String returns a redacted representation.
func (r SignAttemptRecord) String() string { return signAttemptRecordRedacted }

// GoString returns a redacted representation.
func (r SignAttemptRecord) GoString() string { return signAttemptRecordRedacted }

// Format writes a redacted representation for every formatting verb.
func (r SignAttemptRecord) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, signAttemptRecordRedacted)
}

// AttemptCommitStatus reports whether CommitSignAttempt created or recovered
// the exact durable attempt.
type AttemptCommitStatus uint8

const (
	// AttemptCreated reports that the transaction claimed the presign and
	// created the attempt.
	AttemptCreated AttemptCommitStatus = iota + 1
	// AttemptExistingSame reports that the exact immutable attempt already
	// existed.
	AttemptExistingSame
)

// AttemptCommit is the successful result of CommitSignAttempt.
type AttemptCommit struct {
	Status AttemptCommitStatus
	Record SignAttemptRecord
}

// AttemptOutcomeUnknownError carries the exact non-secret recovery query for a
// mutation whose durable outcome is unknown.
type AttemptOutcomeUnknownError struct {
	Cause error
	Query AttemptQuery
}

// Error returns the public outcome-unknown error string.
func (e *AttemptOutcomeUnknownError) Error() string {
	if e == nil || e.Cause == nil {
		return ErrAttemptOutcomeUnknown.Error()
	}
	return ErrAttemptOutcomeUnknown.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the underlying store error.
func (e *AttemptOutcomeUnknownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is preserves errors.Is(err, ErrAttemptOutcomeUnknown).
func (e *AttemptOutcomeUnknownError) Is(target error) bool {
	return target == ErrAttemptOutcomeUnknown
}

// CutoverFence is the compare-and-swap token returned by BeginCutover.
type CutoverFence struct {
	Token  uint64
	Source GenerationBinding
	Target GenerationBinding
}

// Clone returns an independent copy of the cutover fence.
func (f CutoverFence) Clone() CutoverFence { return f }

// LifecycleStore is the transactional durability boundary for generation
// validation, run leases, presign availability, sign attempts, and cutover.
//
// CommitSignAttempt must atomically validate the current generation, claim the
// available presign, and persist the exact immutable intent and outbox. Any
// non-domain failure from that operation has unknown outcome; callers must use
// QueryAttemptOutcome with the exact query and must never try another intent.
// BeginCutover fences new generation-bound work. CommitCutover must atomically
// compare-and-swap the current generation, install the target, retire the
// source, and burn every still-available presign in the source epoch.
type LifecycleStore interface {
	InstallInitialGeneration(ctx context.Context, binding GenerationBinding, blob, metadata []byte) (GenerationRecord, error)
	LoadCurrentGeneration(ctx context.Context, keyID string) (GenerationRecord, error)

	AcquireRunLease(ctx context.Context, binding GenerationBinding, kind RunKind, sessionID tss.SessionID) (RunLease, error)
	AcquireReshareReceiverLease(ctx context.Context, anchor ReshareReceiverAnchor) (RunLease, error)
	FinishRunLease(ctx context.Context, lease RunLease, outcome RunLeaseOutcome) error
	MarkProtocolRefreshFailed(ctx context.Context, lease RunLease, reason string) (RefreshDisabledRecord, error)

	CommitAvailablePresignFromLease(ctx context.Context, lease RunLease, presignID string, blob, metadata []byte) error
	PreparePresignCandidate(ctx context.Context, binding GenerationBinding, presignID string) (PresignCandidate, error)
	CommitSignAttempt(ctx context.Context, binding GenerationBinding, presignID string, intent SignAttemptIntent, exactOutbox []byte) (AttemptCommit, error)
	QueryAttemptOutcome(ctx context.Context, query AttemptQuery) (SignAttemptRecord, error)
	MarkAttemptDelivered(ctx context.Context, query AttemptQuery, delivery []byte) (SignAttemptRecord, error)
	CompleteAttempt(ctx context.Context, query AttemptQuery, completion []byte) (SignAttemptRecord, error)
	AbortAttempt(ctx context.Context, query AttemptQuery, reason string) (SignAttemptRecord, error)
	BurnPresign(ctx context.Context, binding GenerationBinding, presignID, reason string) error

	BeginCutover(ctx context.Context, source, target GenerationBinding) (CutoverFence, error)
	BeginCutoverFromLease(ctx context.Context, lease RunLease, target GenerationBinding) (CutoverFence, error)
	CommitRetirementFromLease(ctx context.Context, lease RunLease, target GenerationBinding) error
	CommitCutover(ctx context.Context, fence CutoverFence, targetBlob, targetMetadata []byte) (GenerationRecord, error)
	AbortCutover(ctx context.Context, fence CutoverFence, reason string) error
	CommitInitialGenerationFromLease(ctx context.Context, lease RunLease, child GenerationBinding, childBlob, childMetadata []byte) (GenerationRecord, error)
	CommitInitialGenerationFromReshareLease(ctx context.Context, lease RunLease, target GenerationBinding, targetBlob, targetMetadata []byte) (GenerationRecord, error)
}

func validateLifecycleIdentifier(value string) error {
	if value == "" || len(value) > maxLifecycleIdentifierBytes || !utf8.ValidString(value) {
		return ErrInvalidLifecycleRecord
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidLifecycleRecord
		}
	}
	return nil
}

func validateLifecycleReason(reason string) error {
	if reason == "" || len(reason) > maxLifecycleReasonBytes || !utf8.ValidString(reason) {
		return ErrInvalidLifecycleRecord
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidLifecycleRecord
		}
	}
	return nil
}

func validateLifecycleBlob(blob []byte, required bool) error {
	if (required && len(blob) == 0) || len(blob) > maxLifecycleBlobBytes {
		return ErrInvalidLifecycleRecord
	}
	return nil
}

func sameAttemptQuery(record SignAttemptRecord, query AttemptQuery) bool {
	return record.Binding == query.Binding &&
		record.PresignID == query.PresignID &&
		record.Intent.AttemptID == query.AttemptID &&
		bytes.Equal(record.Intent.IntentDigest, query.IntentDigest)
}
