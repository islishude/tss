package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

type storedGeneration struct {
	record GenerationRecord
}

type storedRunLease struct {
	lease RunLease
}

type storedLeaseEffectKind uint8

const (
	storedLeaseEffectPresign storedLeaseEffectKind = iota + 1
	storedLeaseEffectCutover
	storedLeaseEffectRefreshFailed
	storedLeaseEffectChildGeneration
	storedLeaseEffectReshareReceiverGeneration
	storedLeaseEffectRetirement
)

type storedLeaseEffect struct {
	LeaseToken   uint64
	Kind         storedLeaseEffectKind
	PresignID    string
	Target       GenerationBinding
	Digest       []byte
	Reason       string
	CutoverToken uint64
}

type storedPresignState uint8

const (
	storedPresignAvailable storedPresignState = iota + 1
	storedPresignClaimed
	storedPresignBurned
)

type storedPresign struct {
	binding        GenerationBinding
	blob           []byte
	metadata       []byte
	artifactDigest []byte
	state          storedPresignState
	attemptID      string
	reason         string
}

type storedAttempt struct {
	record SignAttemptRecord
}

type storedCutoverState uint8

const (
	storedCutoverActive storedCutoverState = iota + 1
	storedCutoverCommitted
	storedCutoverAborted
)

type storedCutover struct {
	fence                CutoverFence
	state                storedCutoverState
	targetBlobDigest     []byte
	targetMetadataDigest []byte
	reason               string
}

// MemoryLifecycleStore is a mutex-protected reference LifecycleStore. It
// models transaction boundaries but is neither durable nor encrypted.
type MemoryLifecycleStore struct {
	mu sync.Mutex

	generations map[GenerationBinding]*storedGeneration
	current     map[string]GenerationBinding

	leasesByToken    map[uint64]*storedRunLease
	leaseBySession   map[tss.SessionID]uint64
	leaseEffects     map[uint64]*storedLeaseEffect
	refreshDisabled  map[string]RefreshDisabledRecord
	reshareReceivers map[uint64]ReshareReceiverAnchor
	attempts         map[string]*storedAttempt
	presigns         map[string]*storedPresign

	cutoversByToken map[uint64]*storedCutover
	cutoverByKey    map[string]uint64

	nextLeaseToken   uint64
	nextCutoverToken uint64
}

var _ LifecycleStore = (*MemoryLifecycleStore)(nil)

// NewMemoryLifecycleStore returns an empty reference lifecycle store.
func NewMemoryLifecycleStore() *MemoryLifecycleStore {
	return &MemoryLifecycleStore{
		generations:      make(map[GenerationBinding]*storedGeneration),
		current:          make(map[string]GenerationBinding),
		leasesByToken:    make(map[uint64]*storedRunLease),
		leaseBySession:   make(map[tss.SessionID]uint64),
		leaseEffects:     make(map[uint64]*storedLeaseEffect),
		refreshDisabled:  make(map[string]RefreshDisabledRecord),
		reshareReceivers: make(map[uint64]ReshareReceiverAnchor),
		attempts:         make(map[string]*storedAttempt),
		presigns:         make(map[string]*storedPresign),
		cutoversByToken:  make(map[uint64]*storedCutover),
		cutoverByKey:     make(map[string]uint64),
	}
}

// InstallInitialGeneration installs binding only when keyID has no current or
// historical generation and no active keygen lease remains.
func (s *MemoryLifecycleStore) InstallInitialGeneration(ctx context.Context, binding GenerationBinding, blob, metadata []byte) (GenerationRecord, error) {
	if err := ctx.Err(); err != nil {
		return GenerationRecord{}, err
	}
	if err := binding.Validate(); err != nil {
		return GenerationRecord{}, err
	}
	if err := validateLifecycleBlob(blob, true); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid generation blob", err)
	}
	if err := validateLifecycleBlob(metadata, false); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid generation metadata", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.current[binding.KeyID]; ok {
		stored := s.generations[current]
		if current == binding && stored != nil && stored.record.Status == GenerationCurrent &&
			bytes.Equal(stored.record.Blob, blob) && bytes.Equal(stored.record.Metadata, metadata) {
			return stored.record.Clone(), nil
		}
		return GenerationRecord{}, ErrGenerationConflict
	}
	if s.hasGenerationForKeyLocked(binding.KeyID) {
		return GenerationRecord{}, ErrGenerationConflict
	}
	if s.hasActiveLeaseForKeyLocked(binding.KeyID) {
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	record := GenerationRecord{
		Binding:  binding,
		Blob:     bytes.Clone(blob),
		Metadata: bytes.Clone(metadata),
		Status:   GenerationCurrent,
	}
	s.generations[binding] = &storedGeneration{record: record}
	s.current[binding.KeyID] = binding
	return record.Clone(), nil
}

// LoadCurrentGeneration returns an independent snapshot of the current
// generation for keyID.
func (s *MemoryLifecycleStore) LoadCurrentGeneration(ctx context.Context, keyID string) (GenerationRecord, error) {
	if err := ctx.Err(); err != nil {
		return GenerationRecord{}, err
	}
	if err := validateLifecycleIdentifier(keyID); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid key id", ErrInvalidLifecycleRecord)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.current[keyID]
	if !ok {
		return GenerationRecord{}, ErrGenerationNotCurrent
	}
	record, ok := s.generations[binding]
	if !ok || record.record.Status != GenerationCurrent {
		return GenerationRecord{}, ErrLifecycleCorrupt
	}
	return record.record.Clone(), nil
}

// AcquireRunLease validates binding against the current generation and creates
// a fencing token for sessionID. Refresh, reshare, and keygen leases are
// exclusive; only sign and presign leases may coexist.
func (s *MemoryLifecycleStore) AcquireRunLease(ctx context.Context, binding GenerationBinding, kind RunKind, sessionID tss.SessionID) (RunLease, error) {
	if err := ctx.Err(); err != nil {
		return RunLease{}, err
	}
	if err := binding.Validate(); err != nil {
		return RunLease{}, err
	}
	if !validLeaseRunKind(kind) || !sessionID.Valid() {
		return RunLease{}, ErrInvalidLifecycleRecord
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == RunRefresh {
		if _, disabled := s.refreshDisabled[binding.KeyID]; disabled {
			return RunLease{}, ErrRefreshDisabled
		}
	}
	if token, ok := s.leaseBySession[sessionID]; ok {
		record := s.leasesByToken[token]
		if record == nil {
			return RunLease{}, ErrLifecycleCorrupt
		}
		if _, receiverJoin := s.reshareReceivers[token]; receiverJoin {
			return RunLease{}, ErrSessionAlreadyUsed
		}
		lease := record.lease
		if lease.Binding == binding && lease.Kind == kind && lease.SessionID == sessionID && lease.State == RunLeaseActive {
			return lease.Clone(), nil
		}
		return RunLease{}, ErrSessionAlreadyUsed
	}
	if kind == RunKeygen {
		if _, ok := s.current[binding.KeyID]; ok || s.hasGenerationForKeyLocked(binding.KeyID) {
			return RunLease{}, ErrGenerationConflict
		}
		if s.hasActiveLeaseForKeyLocked(binding.KeyID) {
			return RunLease{}, ErrRunLeaseConflict
		}
	} else {
		if !s.isCurrentLocked(binding) {
			return RunLease{}, ErrGenerationNotCurrent
		}
		if _, fenced := s.cutoverByKey[binding.KeyID]; fenced {
			return RunLease{}, ErrRunLeaseConflict
		}
		if s.hasIncompatibleLeaseLocked(binding, kind) {
			return RunLease{}, ErrRunLeaseConflict
		}
	}
	s.nextLeaseToken++
	lease := RunLease{
		Token:     s.nextLeaseToken,
		Binding:   binding,
		Kind:      kind,
		SessionID: sessionID,
		State:     RunLeaseActive,
	}
	s.leasesByToken[lease.Token] = &storedRunLease{lease: lease}
	s.leaseBySession[sessionID] = lease.Token
	return lease.Clone(), nil
}

// AcquireReshareReceiverLease durably anchors a new-only receiver's complete
// public source view and creates an exclusive RunReshare lease without making
// the source binding a locally signable generation.
func (s *MemoryLifecycleStore) AcquireReshareReceiverLease(ctx context.Context, anchor ReshareReceiverAnchor) (RunLease, error) {
	if err := ctx.Err(); err != nil {
		return RunLease{}, err
	}
	if err := anchor.Validate(); err != nil {
		return RunLease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if token, ok := s.leaseBySession[anchor.SessionID]; ok {
		record := s.leasesByToken[token]
		storedAnchor, receiverJoin := s.reshareReceivers[token]
		if record == nil || !receiverJoin {
			return RunLease{}, ErrSessionAlreadyUsed
		}
		if record.lease.State == RunLeaseActive && reshareReceiverAnchorsEqual(storedAnchor, anchor) {
			return record.lease.Clone(), nil
		}
		return RunLease{}, ErrSessionAlreadyUsed
	}
	if _, current := s.current[anchor.Source.KeyID]; current {
		return RunLease{}, ErrGenerationConflict
	}
	if s.hasActiveLeaseForKeyLocked(anchor.Source.KeyID) {
		return RunLease{}, ErrRunLeaseConflict
	}
	if _, fenced := s.cutoverByKey[anchor.Source.KeyID]; fenced {
		return RunLease{}, ErrRunLeaseConflict
	}
	if s.hasNonTerminalAttemptForKeyLocked(anchor.Source.KeyID) {
		return RunLease{}, ErrRunLeaseConflict
	}
	if s.hasKeyGenerationLocked(anchor.Source.KeyID, anchor.TargetKeyGeneration) {
		return RunLease{}, ErrGenerationConflict
	}
	s.nextLeaseToken++
	lease := RunLease{
		Token:     s.nextLeaseToken,
		Binding:   anchor.Source,
		Kind:      RunReshare,
		SessionID: anchor.SessionID,
		State:     RunLeaseActive,
	}
	s.leasesByToken[lease.Token] = &storedRunLease{lease: lease}
	s.leaseBySession[lease.SessionID] = lease.Token
	s.reshareReceivers[lease.Token] = anchor.Clone()
	return lease.Clone(), nil
}

// FinishRunLease records an exact active lease as completed or aborted.
func (s *MemoryLifecycleStore) FinishRunLease(ctx context.Context, lease RunLease, outcome RunLeaseOutcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRunLease(lease); err != nil {
		return err
	}
	if outcome != LeaseCompleted && outcome != LeaseAborted {
		return ErrInvalidLifecycleRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.leasesByToken[lease.Token]
	if !ok {
		return ErrRunLeaseNotFound
	}
	stored := record.lease
	if stored.Binding != lease.Binding || stored.Kind != lease.Kind || stored.SessionID != lease.SessionID {
		return ErrRunLeaseConflict
	}
	wanted := RunLeaseCompleted
	if outcome == LeaseAborted {
		wanted = RunLeaseAborted
	}
	if stored.State == wanted {
		return nil
	}
	if stored.State != RunLeaseActive {
		return ErrRunLeaseConflict
	}
	if _, receiverJoin := s.reshareReceivers[lease.Token]; receiverJoin {
		if outcome != LeaseAborted {
			return ErrRunLeaseConflict
		}
		delete(s.reshareReceivers, lease.Token)
	}
	record.lease.State = wanted
	return nil
}

// MarkProtocolRefreshFailed atomically disables future refreshes for the key
// lineage and terminates the exact active refresh lease as aborted.
func (s *MemoryLifecycleStore) MarkProtocolRefreshFailed(ctx context.Context, lease RunLease, reason string) (RefreshDisabledRecord, error) {
	if err := ctx.Err(); err != nil {
		return RefreshDisabledRecord{}, err
	}
	if err := validateRunLease(lease); err != nil || lease.Kind != RunRefresh || lease.State != RunLeaseActive {
		return RefreshDisabledRecord{}, ErrInvalidLifecycleRecord
	}
	if err := validateLifecycleReason(reason); err != nil {
		return RefreshDisabledRecord{}, fmt.Errorf("%w: invalid refresh failure reason", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if effect := s.leaseEffects[lease.Token]; effect != nil {
		if effect.Kind == storedLeaseEffectRefreshFailed && effect.Reason == reason {
			record, ok := s.refreshDisabled[lease.Binding.KeyID]
			if !ok || record.SessionID != lease.SessionID || record.Reason != reason {
				return RefreshDisabledRecord{}, ErrLifecycleCorrupt
			}
			return record.Clone(), nil
		}
		return RefreshDisabledRecord{}, ErrRunLeaseConflict
	}
	stored, err := s.exactActiveLeaseLocked(lease)
	if err != nil {
		return RefreshDisabledRecord{}, err
	}
	if _, exists := s.refreshDisabled[lease.Binding.KeyID]; exists {
		return RefreshDisabledRecord{}, ErrRefreshDisabled
	}
	record := RefreshDisabledRecord{KeyID: lease.Binding.KeyID, SessionID: lease.SessionID, Reason: reason}
	s.refreshDisabled[record.KeyID] = record
	stored.lease.State = RunLeaseAborted
	s.leaseEffects[lease.Token] = &storedLeaseEffect{LeaseToken: lease.Token, Kind: storedLeaseEffectRefreshFailed, Reason: reason}
	return record.Clone(), nil
}

// CommitAvailablePresignFromLease atomically stores one available presign and
// completes the exact active presign lease.
func (s *MemoryLifecycleStore) CommitAvailablePresignFromLease(ctx context.Context, lease RunLease, presignID string, blob, metadata []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRunLease(lease); err != nil || lease.Kind != RunPresign || lease.State != RunLeaseActive {
		return ErrInvalidLifecycleRecord
	}
	if err := validatePresignInput(lease.Binding, presignID, blob, metadata); err != nil {
		return err
	}
	digest := leaseEffectArtifactDigest("presign", lease.Binding, presignID, blob, metadata)
	artifactDigest := sha256.Sum256(metadata)
	s.mu.Lock()
	defer s.mu.Unlock()
	if effect := s.leaseEffects[lease.Token]; effect != nil {
		if effect.Kind == storedLeaseEffectPresign && effect.PresignID == presignID && bytes.Equal(effect.Digest, digest) {
			presign := s.presigns[presignID]
			if presign == nil || presign.binding != lease.Binding || !bytes.Equal(presign.artifactDigest, artifactDigest[:]) {
				return ErrLifecycleCorrupt
			}
			if presign.state == storedPresignAvailable && (!bytes.Equal(presign.blob, blob) || !bytes.Equal(presign.metadata, metadata)) {
				return ErrLifecycleCorrupt
			}
			return nil
		}
		return ErrRunLeaseConflict
	}
	stored, err := s.exactActiveLeaseLocked(lease)
	if err != nil {
		return err
	}
	if !s.isCurrentLocked(lease.Binding) {
		return ErrGenerationNotCurrent
	}
	if _, fenced := s.cutoverByKey[lease.Binding.KeyID]; fenced {
		return ErrRunLeaseConflict
	}
	if _, exists := s.presigns[presignID]; exists {
		return ErrPresignUnavailable
	}
	if s.hasConflictingPresignArtifactLocked(presignID, artifactDigest[:]) {
		return ErrPresignUnavailable
	}
	s.presigns[presignID] = &storedPresign{
		binding:        lease.Binding,
		blob:           bytes.Clone(blob),
		metadata:       bytes.Clone(metadata),
		artifactDigest: bytes.Clone(artifactDigest[:]),
		state:          storedPresignAvailable,
	}
	stored.lease.State = RunLeaseCompleted
	s.leaseEffects[lease.Token] = &storedLeaseEffect{
		LeaseToken: lease.Token, Kind: storedLeaseEffectPresign, PresignID: presignID, Digest: bytes.Clone(digest),
	}
	return nil
}

// PreparePresignCandidate returns a read-only snapshot without claiming or
// mutating the presign.
func (s *MemoryLifecycleStore) PreparePresignCandidate(ctx context.Context, binding GenerationBinding, presignID string) (PresignCandidate, error) {
	if err := ctx.Err(); err != nil {
		return PresignCandidate{}, err
	}
	if err := binding.Validate(); err != nil {
		return PresignCandidate{}, err
	}
	if err := validateLifecycleIdentifier(presignID); err != nil {
		return PresignCandidate{}, fmt.Errorf("%w: invalid presign id", ErrInvalidLifecycleRecord)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isCurrentLocked(binding) {
		return PresignCandidate{}, ErrGenerationNotCurrent
	}
	if _, fenced := s.cutoverByKey[binding.KeyID]; fenced {
		return PresignCandidate{}, ErrRunLeaseConflict
	}
	record, ok := s.presigns[presignID]
	if !ok || record.binding != binding {
		return PresignCandidate{}, ErrPresignUnavailable
	}
	switch record.state {
	case storedPresignAvailable:
		return PresignCandidate{
			Binding:   binding,
			PresignID: presignID,
			Blob:      bytes.Clone(record.blob),
			Metadata:  bytes.Clone(record.metadata),
		}, nil
	case storedPresignBurned:
		return PresignCandidate{}, ErrPresignBurned
	default:
		return PresignCandidate{}, ErrPresignUnavailable
	}
}

// CommitSignAttempt atomically validates the current generation, checks the
// active signing lease, claims the presign, and commits the exact outbox.
func (s *MemoryLifecycleStore) CommitSignAttempt(ctx context.Context, binding GenerationBinding, presignID string, intent SignAttemptIntent, exactOutbox []byte) (AttemptCommit, error) {
	if err := ctx.Err(); err != nil {
		return AttemptCommit{}, err
	}
	if err := binding.Validate(); err != nil {
		return AttemptCommit{}, err
	}
	if err := validateLifecycleIdentifier(presignID); err != nil {
		return AttemptCommit{}, fmt.Errorf("%w: invalid presign id", ErrInvalidLifecycleRecord)
	}
	if err := intent.Validate(); err != nil {
		return AttemptCommit{}, err
	}
	if err := validateLifecycleBlob(exactOutbox, true); err != nil {
		return AttemptCommit{}, fmt.Errorf("%w: invalid exact outbox", err)
	}
	outboxDigest := sha256.Sum256(exactOutbox)

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.attempts[intent.AttemptID]; ok {
		if !sameBaseAttempt(existing.record, binding, presignID, intent, outboxDigest[:]) {
			if existing.record.PresignID == presignID && bytes.Equal(existing.record.Intent.IntentDigest, intent.IntentDigest) {
				return AttemptCommit{}, ErrAttemptNonDeterminism
			}
			return AttemptCommit{}, ErrAttemptConflict
		}
		return AttemptCommit{Status: AttemptExistingSame, Record: existing.record.Clone()}, nil
	}
	if !s.isCurrentLocked(binding) {
		return AttemptCommit{}, ErrGenerationNotCurrent
	}
	if _, fenced := s.cutoverByKey[binding.KeyID]; fenced {
		return AttemptCommit{}, ErrRunLeaseConflict
	}
	if !s.hasActiveSignLeaseLocked(binding, intent.SessionID) {
		return AttemptCommit{}, ErrRunLeaseNotFound
	}
	presign, ok := s.presigns[presignID]
	if !ok || presign.binding != binding {
		return AttemptCommit{}, ErrPresignUnavailable
	}
	switch presign.state {
	case storedPresignBurned:
		return AttemptCommit{}, ErrPresignBurned
	case storedPresignClaimed:
		attempt := s.attempts[presign.attemptID]
		if attempt == nil {
			return AttemptCommit{}, ErrLifecycleCorrupt
		}
		if bytes.Equal(attempt.record.Intent.IntentDigest, intent.IntentDigest) {
			return AttemptCommit{}, ErrAttemptNonDeterminism
		}
		return AttemptCommit{}, ErrAttemptConflict
	case storedPresignAvailable:
	default:
		return AttemptCommit{}, ErrLifecycleCorrupt
	}
	record := SignAttemptRecord{
		Binding:         binding,
		PresignID:       presignID,
		Intent:          intent.Clone(),
		PresignMetadata: bytes.Clone(presign.metadata),
		ExactOutbox:     bytes.Clone(exactOutbox),
		OutboxDigest:    bytes.Clone(outboxDigest[:]),
	}
	s.attempts[intent.AttemptID] = &storedAttempt{record: record}
	presign.state = storedPresignClaimed
	presign.attemptID = intent.AttemptID
	clearBytes(presign.blob)
	clearBytes(presign.metadata)
	presign.blob = nil
	presign.metadata = nil
	return AttemptCommit{Status: AttemptCreated, Record: record.Clone()}, nil
}

// QueryAttemptOutcome returns only the exact bound attempt named by query.
func (s *MemoryLifecycleStore) QueryAttemptOutcome(ctx context.Context, query AttemptQuery) (SignAttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := query.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queryAttemptLocked(query)
}

// MarkAttemptDelivered durably records exact delivery evidence. Repeating the
// same evidence is idempotent; conflicting evidence fails closed.
func (s *MemoryLifecycleStore) MarkAttemptDelivered(ctx context.Context, query AttemptQuery, delivery []byte) (SignAttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := query.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := validateLifecycleBlob(delivery, true); err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: invalid delivery evidence", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.mutableAttemptLocked(query)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if record.Aborted {
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	if record.Delivered {
		if bytes.Equal(record.Delivery, delivery) {
			return record.Clone(), nil
		}
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	record.Delivery = bytes.Clone(delivery)
	record.Delivered = true
	s.clearAttemptSecretsIfTerminalLocked(record)
	return record.Clone(), nil
}

// CompleteAttempt durably records an exact completion result. The attempt is
// terminal only when delivery is also durable.
func (s *MemoryLifecycleStore) CompleteAttempt(ctx context.Context, query AttemptQuery, completion []byte) (SignAttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := query.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := validateLifecycleBlob(completion, true); err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: invalid completion", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.mutableAttemptLocked(query)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if record.Aborted {
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	if record.Completed {
		if bytes.Equal(record.Completion, completion) {
			return record.Clone(), nil
		}
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	record.Completion = bytes.Clone(completion)
	record.Completed = true
	s.clearAttemptSecretsIfTerminalLocked(record)
	return record.Clone(), nil
}

// AbortAttempt durably terminates an exact attempt, burns its presign, and
// clears retained secret recovery material.
func (s *MemoryLifecycleStore) AbortAttempt(ctx context.Context, query AttemptQuery, reason string) (SignAttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := query.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := validateLifecycleReason(reason); err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: invalid abort reason", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.mutableAttemptLocked(query)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if record.Terminal() && !record.Aborted {
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	if record.Aborted {
		if record.AbortReason == reason {
			return record.Clone(), nil
		}
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	record.Aborted = true
	record.AbortReason = reason
	clearBytes(record.ExactOutbox)
	record.ExactOutbox = nil
	presign := s.presigns[record.PresignID]
	if presign == nil || presign.state != storedPresignClaimed || presign.attemptID != record.Intent.AttemptID {
		return SignAttemptRecord{}, ErrLifecycleCorrupt
	}
	presign.state = storedPresignBurned
	presign.reason = reason
	return record.Clone(), nil
}

// BurnPresign durably tombstones an available presign. A claimed presign can
// only be terminated through AbortAttempt or exact-attempt completion.
func (s *MemoryLifecycleStore) BurnPresign(ctx context.Context, binding GenerationBinding, presignID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := validateLifecycleIdentifier(presignID); err != nil {
		return fmt.Errorf("%w: invalid presign id", ErrInvalidLifecycleRecord)
	}
	if err := validateLifecycleReason(reason); err != nil {
		return fmt.Errorf("%w: invalid burn reason", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	presign, ok := s.presigns[presignID]
	if !ok || presign.binding != binding {
		return ErrPresignUnavailable
	}
	switch presign.state {
	case storedPresignAvailable:
		clearBytes(presign.blob)
		clearBytes(presign.metadata)
		presign.blob = nil
		presign.metadata = nil
		presign.state = storedPresignBurned
		presign.reason = reason
		return nil
	case storedPresignBurned:
		if presign.reason == reason {
			return nil
		}
		return ErrPresignBurned
	case storedPresignClaimed:
		return ErrAttemptConflict
	default:
		return ErrLifecycleCorrupt
	}
}

// BeginCutover atomically fences source after verifying it is current and all
// generation-bound leases and signing attempts are terminal.
func (s *MemoryLifecycleStore) BeginCutover(ctx context.Context, source, target GenerationBinding) (CutoverFence, error) {
	if err := ctx.Err(); err != nil {
		return CutoverFence{}, err
	}
	if err := validateCutoverBindings(source, target); err != nil {
		return CutoverFence{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if token, ok := s.cutoverByKey[source.KeyID]; ok {
		cutover := s.cutoversByToken[token]
		if cutover == nil || cutover.state != storedCutoverActive {
			return CutoverFence{}, ErrLifecycleCorrupt
		}
		if cutover.fence.Source == source && cutover.fence.Target == target {
			return cutover.fence.Clone(), nil
		}
		return CutoverFence{}, ErrCutoverConflict
	}
	if !s.isCurrentLocked(source) {
		return CutoverFence{}, ErrGenerationNotCurrent
	}
	if _, exists := s.generations[target]; exists {
		return CutoverFence{}, ErrGenerationConflict
	}
	if s.hasActiveLeaseLocked(source) || s.hasNonTerminalAttemptLocked(source) {
		return CutoverFence{}, ErrRunLeaseConflict
	}
	s.nextCutoverToken++
	fence := CutoverFence{Token: s.nextCutoverToken, Source: source, Target: target}
	s.cutoversByToken[fence.Token] = &storedCutover{fence: fence, state: storedCutoverActive}
	s.cutoverByKey[source.KeyID] = fence.Token
	return fence.Clone(), nil
}

// BeginCutoverFromLease atomically completes the exact successful refresh or
// reshare lease and establishes the generation fence. Child derivation creates
// a distinct key lineage through CommitInitialGenerationFromLease instead.
func (s *MemoryLifecycleStore) BeginCutoverFromLease(ctx context.Context, lease RunLease, target GenerationBinding) (CutoverFence, error) {
	if err := ctx.Err(); err != nil {
		return CutoverFence{}, err
	}
	if err := validateRunLease(lease); err != nil || lease.State != RunLeaseActive || !cutoverLeaseRunKind(lease.Kind) {
		return CutoverFence{}, ErrInvalidLifecycleRecord
	}
	if err := validateCutoverBindings(lease.Binding, target); err != nil {
		return CutoverFence{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if effect := s.leaseEffects[lease.Token]; effect != nil {
		if effect.Kind != storedLeaseEffectCutover || effect.Target != target || effect.CutoverToken == 0 {
			return CutoverFence{}, ErrRunLeaseConflict
		}
		cutover := s.cutoversByToken[effect.CutoverToken]
		if cutover == nil || cutover.fence.Source != lease.Binding || cutover.fence.Target != target {
			return CutoverFence{}, ErrLifecycleCorrupt
		}
		return cutover.fence.Clone(), nil
	}
	stored, err := s.exactActiveLeaseLocked(lease)
	if err != nil {
		return CutoverFence{}, err
	}
	if _, active := s.cutoverByKey[lease.Binding.KeyID]; active {
		return CutoverFence{}, ErrCutoverConflict
	}
	if !s.isCurrentLocked(lease.Binding) {
		return CutoverFence{}, ErrGenerationNotCurrent
	}
	if _, exists := s.generations[target]; exists {
		return CutoverFence{}, ErrGenerationConflict
	}
	if s.hasOtherActiveLeaseLocked(lease.Binding, lease.Token) || s.hasNonTerminalAttemptLocked(lease.Binding) {
		return CutoverFence{}, ErrRunLeaseConflict
	}
	s.nextCutoverToken++
	fence := CutoverFence{Token: s.nextCutoverToken, Source: lease.Binding, Target: target}
	s.cutoversByToken[fence.Token] = &storedCutover{fence: fence, state: storedCutoverActive}
	s.cutoverByKey[lease.Binding.KeyID] = fence.Token
	stored.lease.State = RunLeaseCompleted
	s.leaseEffects[lease.Token] = &storedLeaseEffect{
		LeaseToken: lease.Token, Kind: storedLeaseEffectCutover, Target: target, CutoverToken: fence.Token,
	}
	return fence.Clone(), nil
}

// CommitRetirementFromLease atomically completes an old-only dealer's exact
// active reshare lease, retires and clears the source generation, and burns
// every available presign from the source epoch without installing a local
// target generation.
func (s *MemoryLifecycleStore) CommitRetirementFromLease(ctx context.Context, lease RunLease, target GenerationBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRunLease(lease); err != nil || lease.Kind != RunReshare || lease.State != RunLeaseActive {
		return ErrInvalidLifecycleRecord
	}
	if err := validateCutoverBindings(lease.Binding, target); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if effect := s.leaseEffects[lease.Token]; effect != nil {
		if effect.Kind != storedLeaseEffectRetirement || effect.Target != target {
			return ErrRunLeaseConflict
		}
		source := s.generations[lease.Binding]
		if source == nil || source.record.Status != GenerationRetired || len(source.record.Blob) != 0 ||
			len(source.record.Metadata) != 0 {
			return ErrLifecycleCorrupt
		}
		if _, current := s.current[lease.Binding.KeyID]; current {
			return ErrLifecycleCorrupt
		}
		return nil
	}
	stored, err := s.exactActiveLeaseLocked(lease)
	if err != nil {
		return err
	}
	if _, receiverJoin := s.reshareReceivers[lease.Token]; receiverJoin {
		return ErrRunLeaseConflict
	}
	if !s.isCurrentLocked(lease.Binding) {
		return ErrGenerationNotCurrent
	}
	if _, fenced := s.cutoverByKey[lease.Binding.KeyID]; fenced {
		return ErrRunLeaseConflict
	}
	if s.hasOtherActiveLeaseLocked(lease.Binding, lease.Token) || s.hasNonTerminalAttemptLocked(lease.Binding) {
		return ErrRunLeaseConflict
	}
	if _, exists := s.generations[target]; exists {
		return ErrGenerationConflict
	}
	source := s.generations[lease.Binding]
	if source == nil || source.record.Status != GenerationCurrent {
		return ErrLifecycleCorrupt
	}
	source.record.Status = GenerationRetired
	clearBytes(source.record.Blob)
	clearBytes(source.record.Metadata)
	source.record.Blob = nil
	source.record.Metadata = nil
	delete(s.current, lease.Binding.KeyID)
	s.burnEpochPresignsLocked(lease.Binding.KeyID, lease.Binding.EpochID)
	stored.lease.State = RunLeaseCompleted
	s.leaseEffects[lease.Token] = &storedLeaseEffect{
		LeaseToken: lease.Token,
		Kind:       storedLeaseEffectRetirement,
		Target:     target,
	}
	return nil
}

// CommitCutover atomically installs target, retires source, and burns every
// still-available presign in the source epoch.
func (s *MemoryLifecycleStore) CommitCutover(ctx context.Context, fence CutoverFence, targetBlob, targetMetadata []byte) (GenerationRecord, error) {
	if err := ctx.Err(); err != nil {
		return GenerationRecord{}, err
	}
	if err := validateCutoverFence(fence); err != nil {
		return GenerationRecord{}, err
	}
	if err := validateLifecycleBlob(targetBlob, true); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid target generation blob", err)
	}
	if err := validateLifecycleBlob(targetMetadata, false); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid target generation metadata", err)
	}
	targetBlobDigest := sha256.Sum256(targetBlob)
	targetMetadataDigest := sha256.Sum256(targetMetadata)
	s.mu.Lock()
	defer s.mu.Unlock()
	cutover, ok := s.cutoversByToken[fence.Token]
	if !ok || cutover.fence != fence {
		return GenerationRecord{}, ErrCutoverConflict
	}
	if cutover.state == storedCutoverCommitted {
		if !bytes.Equal(cutover.targetBlobDigest, targetBlobDigest[:]) ||
			!bytes.Equal(cutover.targetMetadataDigest, targetMetadataDigest[:]) {
			return GenerationRecord{}, ErrCutoverConflict
		}
		target := s.generations[fence.Target]
		if target == nil || target.record.Status != GenerationCurrent {
			return GenerationRecord{}, ErrLifecycleCorrupt
		}
		return target.record.Clone(), nil
	}
	if cutover.state != storedCutoverActive {
		return GenerationRecord{}, ErrCutoverConflict
	}
	if token, active := s.cutoverByKey[fence.Source.KeyID]; !active || token != fence.Token {
		return GenerationRecord{}, ErrCutoverConflict
	}
	if !s.isCurrentLocked(fence.Source) {
		return GenerationRecord{}, ErrGenerationConflict
	}
	if s.hasActiveLeaseLocked(fence.Source) || s.hasNonTerminalAttemptLocked(fence.Source) {
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	if _, exists := s.generations[fence.Target]; exists {
		return GenerationRecord{}, ErrGenerationConflict
	}

	source := s.generations[fence.Source]
	if source == nil || source.record.Status != GenerationCurrent {
		return GenerationRecord{}, ErrLifecycleCorrupt
	}
	target := GenerationRecord{
		Binding:  fence.Target,
		Blob:     bytes.Clone(targetBlob),
		Metadata: bytes.Clone(targetMetadata),
		Status:   GenerationCurrent,
	}
	s.generations[fence.Target] = &storedGeneration{record: target}
	s.current[fence.Source.KeyID] = fence.Target
	source.record.Status = GenerationRetired
	clearBytes(source.record.Blob)
	clearBytes(source.record.Metadata)
	source.record.Blob = nil
	source.record.Metadata = nil
	s.burnEpochPresignsLocked(fence.Source.KeyID, fence.Source.EpochID)
	cutover.state = storedCutoverCommitted
	cutover.targetBlobDigest = bytes.Clone(targetBlobDigest[:])
	cutover.targetMetadataDigest = bytes.Clone(targetMetadataDigest[:])
	delete(s.cutoverByKey, fence.Source.KeyID)
	return target.Clone(), nil
}

// AbortCutover removes an exact active fence without changing the current
// generation. Repeating the exact abort is idempotent.
func (s *MemoryLifecycleStore) AbortCutover(ctx context.Context, fence CutoverFence, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCutoverFence(fence); err != nil {
		return err
	}
	if err := validateLifecycleReason(reason); err != nil {
		return fmt.Errorf("%w: invalid cutover abort reason", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutover, ok := s.cutoversByToken[fence.Token]
	if !ok || cutover.fence != fence {
		return ErrCutoverConflict
	}
	if cutover.state == storedCutoverAborted {
		if cutover.reason == reason {
			return nil
		}
		return ErrCutoverConflict
	}
	if cutover.state != storedCutoverActive {
		return ErrCutoverConflict
	}
	if token, active := s.cutoverByKey[fence.Source.KeyID]; !active || token != fence.Token {
		return ErrCutoverConflict
	}
	cutover.state = storedCutoverAborted
	cutover.reason = reason
	delete(s.cutoverByKey, fence.Source.KeyID)
	return nil
}

// CommitInitialGenerationFromLease atomically completes an exact child
// derivation lease on the parent and installs a first generation for a distinct
// child key ID.
func (s *MemoryLifecycleStore) CommitInitialGenerationFromLease(ctx context.Context, lease RunLease, child GenerationBinding, childBlob, childMetadata []byte) (GenerationRecord, error) {
	if err := ctx.Err(); err != nil {
		return GenerationRecord{}, err
	}
	if err := validateRunLease(lease); err != nil || lease.Kind != RunChildDerivation || lease.State != RunLeaseActive {
		return GenerationRecord{}, ErrInvalidLifecycleRecord
	}
	if err := child.Validate(); err != nil || child.KeyID == lease.Binding.KeyID || child.EpochID == lease.Binding.EpochID {
		return GenerationRecord{}, ErrInvalidLifecycleRecord
	}
	if err := validateLifecycleBlob(childBlob, true); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid child generation blob", err)
	}
	if err := validateLifecycleBlob(childMetadata, true); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid child generation metadata", err)
	}
	digest := leaseEffectArtifactDigest("child-generation", child, child.KeyID, childBlob, childMetadata)
	s.mu.Lock()
	defer s.mu.Unlock()
	if effect := s.leaseEffects[lease.Token]; effect != nil {
		if effect.Kind == storedLeaseEffectChildGeneration && effect.Target == child && bytes.Equal(effect.Digest, digest) {
			generation := s.generations[child]
			if generation == nil || generation.record.Status != GenerationCurrent ||
				!bytes.Equal(generation.record.Blob, childBlob) || !bytes.Equal(generation.record.Metadata, childMetadata) {
				return GenerationRecord{}, ErrLifecycleCorrupt
			}
			return generation.record.Clone(), nil
		}
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	stored, err := s.exactActiveLeaseLocked(lease)
	if err != nil {
		return GenerationRecord{}, err
	}
	if !s.isCurrentLocked(lease.Binding) {
		return GenerationRecord{}, ErrGenerationNotCurrent
	}
	if _, fenced := s.cutoverByKey[lease.Binding.KeyID]; fenced {
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	if _, current := s.current[child.KeyID]; current || s.hasGenerationForKeyLocked(child.KeyID) || s.hasActiveLeaseForKeyLocked(child.KeyID) {
		return GenerationRecord{}, ErrGenerationConflict
	}
	record := GenerationRecord{Binding: child, Blob: bytes.Clone(childBlob), Metadata: bytes.Clone(childMetadata), Status: GenerationCurrent}
	s.generations[child] = &storedGeneration{record: record}
	s.current[child.KeyID] = child
	stored.lease.State = RunLeaseCompleted
	s.leaseEffects[lease.Token] = &storedLeaseEffect{
		LeaseToken: lease.Token, Kind: storedLeaseEffectChildGeneration, Target: child, Digest: bytes.Clone(digest),
	}
	return record.Clone(), nil
}

// CommitInitialGenerationFromReshareLease atomically completes a new-only
// receiver join and installs the declared target as the first locally signable
// generation. The public source anchor is removed in the same transition.
func (s *MemoryLifecycleStore) CommitInitialGenerationFromReshareLease(ctx context.Context, lease RunLease, target GenerationBinding, targetBlob, targetMetadata []byte) (GenerationRecord, error) {
	if err := ctx.Err(); err != nil {
		return GenerationRecord{}, err
	}
	if err := validateRunLease(lease); err != nil || lease.Kind != RunReshare || lease.State != RunLeaseActive {
		return GenerationRecord{}, ErrInvalidLifecycleRecord
	}
	if err := target.Validate(); err != nil || target.KeyID != lease.Binding.KeyID || target.KeyGeneration == lease.Binding.KeyGeneration || target.EpochID == lease.Binding.EpochID {
		return GenerationRecord{}, ErrInvalidLifecycleRecord
	}
	if err := validateLifecycleBlob(targetBlob, true); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid reshare target generation blob", err)
	}
	if err := validateLifecycleBlob(targetMetadata, false); err != nil {
		return GenerationRecord{}, fmt.Errorf("%w: invalid reshare target generation metadata", err)
	}
	digest := leaseEffectArtifactDigest("reshare-receiver-generation", target, target.KeyID, targetBlob, targetMetadata)
	s.mu.Lock()
	defer s.mu.Unlock()
	if effect := s.leaseEffects[lease.Token]; effect != nil {
		if effect.Kind == storedLeaseEffectReshareReceiverGeneration && effect.Target == target && bytes.Equal(effect.Digest, digest) {
			generation := s.generations[target]
			if generation == nil || generation.record.Status != GenerationCurrent ||
				!bytes.Equal(generation.record.Blob, targetBlob) || !bytes.Equal(generation.record.Metadata, targetMetadata) {
				return GenerationRecord{}, ErrLifecycleCorrupt
			}
			if _, anchored := s.reshareReceivers[lease.Token]; anchored {
				return GenerationRecord{}, ErrLifecycleCorrupt
			}
			return generation.record.Clone(), nil
		}
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	stored, err := s.exactActiveLeaseLocked(lease)
	if err != nil {
		return GenerationRecord{}, err
	}
	anchor, ok := s.reshareReceivers[lease.Token]
	if !ok || anchor.Source != lease.Binding || anchor.SessionID != lease.SessionID ||
		anchor.TargetKeyGeneration != target.KeyGeneration {
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	if _, current := s.current[target.KeyID]; current {
		return GenerationRecord{}, ErrGenerationConflict
	}
	if s.hasOtherActiveLeaseForKeyLocked(target.KeyID, lease.Token) ||
		s.hasNonTerminalAttemptForKeyLocked(target.KeyID) {
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	if _, fenced := s.cutoverByKey[target.KeyID]; fenced {
		return GenerationRecord{}, ErrRunLeaseConflict
	}
	if s.hasKeyGenerationLocked(target.KeyID, target.KeyGeneration) {
		return GenerationRecord{}, ErrGenerationConflict
	}
	record := GenerationRecord{
		Binding:  target,
		Blob:     bytes.Clone(targetBlob),
		Metadata: bytes.Clone(targetMetadata),
		Status:   GenerationCurrent,
	}
	s.generations[target] = &storedGeneration{record: record}
	s.current[target.KeyID] = target
	stored.lease.State = RunLeaseCompleted
	delete(s.reshareReceivers, lease.Token)
	s.leaseEffects[lease.Token] = &storedLeaseEffect{
		LeaseToken: lease.Token,
		Kind:       storedLeaseEffectReshareReceiverGeneration,
		Target:     target,
		Digest:     bytes.Clone(digest),
	}
	return record.Clone(), nil
}

func (s *MemoryLifecycleStore) isCurrentLocked(binding GenerationBinding) bool {
	current, ok := s.current[binding.KeyID]
	if !ok || current != binding {
		return false
	}
	record := s.generations[binding]
	return record != nil && record.record.Status == GenerationCurrent
}

func (s *MemoryLifecycleStore) hasGenerationForKeyLocked(keyID string) bool {
	for binding := range s.generations {
		if binding.KeyID == keyID {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasKeyGenerationLocked(keyID string, generation KeyGeneration) bool {
	for binding := range s.generations {
		if binding.KeyID == keyID && binding.KeyGeneration == generation {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasConflictingPresignArtifactLocked(presignID string, artifactDigest []byte) bool {
	for existingID, presign := range s.presigns {
		if existingID != presignID && presign != nil && bytes.Equal(presign.artifactDigest, artifactDigest) {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasActiveLeaseForKeyLocked(keyID string) bool {
	for _, record := range s.leasesByToken {
		if record.lease.Binding.KeyID == keyID && record.lease.State == RunLeaseActive {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasOtherActiveLeaseForKeyLocked(keyID string, exceptToken uint64) bool {
	for token, record := range s.leasesByToken {
		if token != exceptToken && record.lease.Binding.KeyID == keyID && record.lease.State == RunLeaseActive {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasActiveLeaseLocked(binding GenerationBinding) bool {
	for _, record := range s.leasesByToken {
		if record.lease.Binding == binding && record.lease.State == RunLeaseActive {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasOtherActiveLeaseLocked(binding GenerationBinding, exceptToken uint64) bool {
	for token, record := range s.leasesByToken {
		if token != exceptToken && record.lease.Binding == binding && record.lease.State == RunLeaseActive {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) exactActiveLeaseLocked(lease RunLease) (*storedRunLease, error) {
	stored := s.leasesByToken[lease.Token]
	if stored == nil {
		return nil, ErrRunLeaseNotFound
	}
	if stored.lease.Binding != lease.Binding || stored.lease.Kind != lease.Kind || stored.lease.SessionID != lease.SessionID {
		return nil, ErrRunLeaseConflict
	}
	if stored.lease.State != RunLeaseActive {
		return nil, ErrRunLeaseConflict
	}
	return stored, nil
}

func (s *MemoryLifecycleStore) hasIncompatibleLeaseLocked(binding GenerationBinding, requested RunKind) bool {
	requestedExclusive := exclusiveLeaseRunKind(requested)
	for _, record := range s.leasesByToken {
		lease := record.lease
		if lease.Binding != binding || lease.State != RunLeaseActive {
			continue
		}
		if requestedExclusive || exclusiveLeaseRunKind(lease.Kind) {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasActiveSignLeaseLocked(binding GenerationBinding, sessionID tss.SessionID) bool {
	token, ok := s.leaseBySession[sessionID]
	if !ok {
		return false
	}
	record := s.leasesByToken[token]
	return record != nil && record.lease.Binding == binding && record.lease.Kind == RunSign && record.lease.State == RunLeaseActive
}

func (s *MemoryLifecycleStore) hasNonTerminalAttemptLocked(binding GenerationBinding) bool {
	for _, attempt := range s.attempts {
		if attempt.record.Binding == binding && !attempt.record.Terminal() {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) hasNonTerminalAttemptForKeyLocked(keyID string) bool {
	for _, attempt := range s.attempts {
		if attempt.record.Binding.KeyID == keyID && !attempt.record.Terminal() {
			return true
		}
	}
	return false
}

func (s *MemoryLifecycleStore) queryAttemptLocked(query AttemptQuery) (SignAttemptRecord, error) {
	attempt, ok := s.attempts[query.AttemptID]
	if !ok {
		return SignAttemptRecord{}, ErrAttemptNotFound
	}
	if !sameAttemptQuery(attempt.record, query) {
		return SignAttemptRecord{}, ErrAttemptConflict
	}
	return attempt.record.Clone(), nil
}

func (s *MemoryLifecycleStore) mutableAttemptLocked(query AttemptQuery) (*SignAttemptRecord, error) {
	attempt, ok := s.attempts[query.AttemptID]
	if !ok {
		return nil, ErrAttemptNotFound
	}
	if !sameAttemptQuery(attempt.record, query) {
		return nil, ErrAttemptConflict
	}
	return &attempt.record, nil
}

func (s *MemoryLifecycleStore) clearAttemptSecretsIfTerminalLocked(record *SignAttemptRecord) {
	if record == nil || !record.Terminal() {
		return
	}
	clearBytes(record.ExactOutbox)
	record.ExactOutbox = nil
}

func (s *MemoryLifecycleStore) burnEpochPresignsLocked(keyID string, epochID EpochID) {
	for _, presign := range s.presigns {
		if presign.binding.KeyID != keyID || presign.binding.EpochID != epochID {
			continue
		}
		switch presign.state {
		case storedPresignAvailable:
			clearBytes(presign.blob)
			clearBytes(presign.metadata)
			presign.blob = nil
			presign.metadata = nil
			presign.state = storedPresignBurned
			presign.reason = "generation cutover"
		case storedPresignClaimed:
			attempt := s.attempts[presign.attemptID]
			if attempt != nil && attempt.record.Terminal() {
				presign.state = storedPresignBurned
				presign.reason = "generation cutover"
			}
		}
	}
}

func validatePresignInput(binding GenerationBinding, presignID string, blob, metadata []byte) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := validateLifecycleIdentifier(presignID); err != nil {
		return fmt.Errorf("%w: invalid presign id", ErrInvalidLifecycleRecord)
	}
	if err := validateLifecycleBlob(blob, true); err != nil {
		return fmt.Errorf("%w: invalid presign blob", err)
	}
	if err := validateLifecycleBlob(metadata, true); err != nil {
		return fmt.Errorf("%w: invalid presign metadata", err)
	}
	return nil
}

func validateRunLease(lease RunLease) error {
	if lease.Token == 0 || lease.State == 0 {
		return ErrInvalidLifecycleRecord
	}
	if err := lease.Binding.Validate(); err != nil {
		return err
	}
	if !validLeaseRunKind(lease.Kind) || !lease.SessionID.Valid() {
		return ErrInvalidLifecycleRecord
	}
	return nil
}

func validLeaseRunKind(kind RunKind) bool {
	switch kind {
	case RunKeygen, RunPresign, RunSign, RunChildDerivation, RunRefresh, RunReshare:
		return true
	default:
		return false
	}
}

func exclusiveLeaseRunKind(kind RunKind) bool {
	switch kind {
	case RunKeygen, RunChildDerivation, RunRefresh, RunReshare:
		return true
	default:
		return false
	}
}

func reshareReceiverAnchorsEqual(a, b ReshareReceiverAnchor) bool {
	return a.Source == b.Source &&
		a.TargetKeyGeneration == b.TargetKeyGeneration &&
		a.SessionID == b.SessionID &&
		bytes.Equal(a.PlanDigest, b.PlanDigest) &&
		bytes.Equal(a.SourceEpochDigest, b.SourceEpochDigest)
}

func cutoverLeaseRunKind(kind RunKind) bool {
	switch kind {
	case RunRefresh, RunReshare:
		return true
	default:
		return false
	}
}

func leaseEffectArtifactDigest(label string, binding GenerationBinding, identifier string, blob, metadata []byte) []byte {
	t := transcript.New("tssrun-lifecycle-lease-effect-v1")
	t.AppendString("kind", label)
	t.AppendString("key_id", binding.KeyID)
	t.AppendString("key_generation", string(binding.KeyGeneration))
	t.AppendBytes("epoch_id", binding.EpochID[:])
	t.AppendString("identifier", identifier)
	blobDigest := sha256.Sum256(blob)
	metadataDigest := sha256.Sum256(metadata)
	t.AppendBytes("blob_digest", blobDigest[:])
	t.AppendBytes("metadata_digest", metadataDigest[:])
	return t.Sum()
}

func validateCutoverBindings(source, target GenerationBinding) error {
	if err := source.Validate(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if source.KeyID != target.KeyID || source.KeyGeneration == target.KeyGeneration || source.EpochID == target.EpochID {
		return fmt.Errorf("%w: invalid source and target bindings", ErrInvalidLifecycleRecord)
	}
	return nil
}

func validateCutoverFence(fence CutoverFence) error {
	if fence.Token == 0 {
		return ErrInvalidLifecycleRecord
	}
	return validateCutoverBindings(fence.Source, fence.Target)
}

func sameBaseAttempt(record SignAttemptRecord, binding GenerationBinding, presignID string, intent SignAttemptIntent, outboxDigest []byte) bool {
	return record.Binding == binding &&
		record.PresignID == presignID &&
		record.Intent.AttemptID == intent.AttemptID &&
		record.Intent.SessionID == intent.SessionID &&
		bytes.Equal(record.Intent.IntentDigest, intent.IntentDigest) &&
		bytes.Equal(record.OutboxDigest, outboxDigest)
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
