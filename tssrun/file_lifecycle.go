package tssrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/islishude/tss"
)

const (
	fileLifecycleKeysDirectory  = "keys"
	fileLifecycleLocksDirectory = "locks"
	fileLifecycleBlobsDirectory = "blobs"
	fileLifecycleManifestName   = "manifest.enc"
	fileLifecycleGlobalKeyID    = "tssrun-global-lifecycle"
)

// FileLifecycleFaultPoint identifies one crash-simulation boundary in the
// immutable-blob and manifest persistence sequence.
type FileLifecycleFaultPoint string

const (
	// FileLifecycleFaultAfterBlobWrite occurs after an immutable ciphertext is
	// fully written but before it is fsynced.
	FileLifecycleFaultAfterBlobWrite FileLifecycleFaultPoint = "after-blob-write"
	// FileLifecycleFaultAfterBlobSync occurs after an immutable ciphertext is
	// fsynced but before its reference can enter a manifest.
	FileLifecycleFaultAfterBlobSync FileLifecycleFaultPoint = "after-blob-fsync"
	// FileLifecycleFaultAfterManifestWrite occurs after the replacement
	// manifest is fully written but before it is fsynced.
	FileLifecycleFaultAfterManifestWrite FileLifecycleFaultPoint = "after-manifest-write"
	// FileLifecycleFaultAfterManifestSync occurs after the replacement
	// manifest is fsynced but before the atomic rename.
	FileLifecycleFaultAfterManifestSync FileLifecycleFaultPoint = "after-manifest-fsync"
	// FileLifecycleFaultAfterManifestRename occurs immediately after the
	// atomic manifest swap but before the containing directory is fsynced. A
	// returned error at this point has unknown outcome.
	FileLifecycleFaultAfterManifestRename FileLifecycleFaultPoint = "after-manifest-rename"
	// FileLifecycleFaultAfterManifestDirectorySync occurs after the atomic
	// manifest swap and its containing directory are fsynced. The transaction is
	// durable even though an injected error must still be reconciled by exact
	// query or idempotent retry.
	FileLifecycleFaultAfterManifestDirectorySync FileLifecycleFaultPoint = "after-manifest-directory-fsync"
)

// FileLifecycleFaultInjector returns an injected crash error at selected
// persistence boundaries. It is intended for deterministic tests.
type FileLifecycleFaultInjector func(FileLifecycleFaultPoint) error

// FileLifecycleStoreOption configures the reference file lifecycle store.
type FileLifecycleStoreOption func(*fileLifecycleStoreConfig) error

type fileLifecycleStoreConfig struct {
	faultInjector FileLifecycleFaultInjector
}

// WithFileLifecycleFaultInjector installs a deterministic crash fault
// injector. Production callers should not set it.
func WithFileLifecycleFaultInjector(injector FileLifecycleFaultInjector) FileLifecycleStoreOption {
	return func(config *fileLifecycleStoreConfig) error {
		if config == nil || injector == nil {
			return ErrInvalidLifecycleRecord
		}
		config.faultInjector = injector
		return nil
	}
}

// FileLifecycleStore is an encrypted reference LifecycleStore backed by one
// atomic manifest covering every key lineage. Each operation takes both its
// lineage OS advisory lock and the manifest OS advisory lock. The manifest lock
// prevents distinct lineages from overwriting one another while the lineage
// lock makes ownership explicit for cross-process callers. Immutable ciphertext
// blobs are fsynced before the encrypted manifest references them; renaming the
// fsynced manifest is the only transaction linearization point.
//
// This passphrase-based implementation is a reference helper. Production
// deployments should use a database transaction and KMS or HSM protection.
type FileLifecycleStore struct {
	mu sync.RWMutex

	directory     string
	passphrase    []byte
	params        tss.PassphraseParams
	faultInjector FileLifecycleFaultInjector
	closed        bool
}

var _ LifecycleStore = (*FileLifecycleStore)(nil)

// NewFileLifecycleStore opens or creates an encrypted reference lifecycle
// store. directory and its store-owned descendants must not be symlinks and
// must be private to the current account. passphrase is copied. A nil params
// value selects [tss.DefaultPassphraseParams].
func NewFileLifecycleStore(directory string, passphrase []byte, params *tss.PassphraseParams, opts ...FileLifecycleStoreOption) (*FileLifecycleStore, error) {
	if directory == "" || len(passphrase) == 0 {
		return nil, ErrInvalidLifecycleRecord
	}
	config := fileLifecycleStoreConfig{}
	for _, opt := range opts {
		if opt == nil {
			return nil, ErrInvalidLifecycleRecord
		}
		if err := opt(&config); err != nil {
			return nil, err
		}
	}
	if params == nil {
		params = tss.DefaultPassphraseParams()
	}
	paramsCopy := *params
	passphraseCopy := append([]byte(nil), passphrase...)
	probe, err := tss.EncryptSignAttemptWithPassphrase([]byte("tssrun-lifecycle-probe"), passphraseCopy, "tssrun-lifecycle-probe", &paramsCopy)
	if err != nil {
		clearBytes(passphraseCopy)
		return nil, fmt.Errorf("validate lifecycle passphrase parameters: %w", err)
	}
	clearBytes(probe)

	absolute, err := filepath.Abs(directory)
	if err != nil {
		clearBytes(passphraseCopy)
		return nil, fmt.Errorf("resolve lifecycle store directory: %w", err)
	}
	if err := preparePrivateLifecycleDirectory(absolute); err != nil {
		clearBytes(passphraseCopy)
		return nil, err
	}
	for _, child := range []string{fileLifecycleKeysDirectory, fileLifecycleLocksDirectory} {
		if err := preparePrivateLifecycleDirectory(filepath.Join(absolute, child)); err != nil {
			clearBytes(passphraseCopy)
			return nil, err
		}
	}
	return &FileLifecycleStore{
		directory:     absolute,
		passphrase:    passphraseCopy,
		params:        paramsCopy,
		faultInjector: config.faultInjector,
	}, nil
}

// Close clears the store's passphrase copy. It does not remove durable state.
func (s *FileLifecycleStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	clearBytes(s.passphrase)
	s.passphrase = nil
	s.closed = true
	return nil
}

// InstallInitialGeneration implements LifecycleStore.
func (s *FileLifecycleStore) InstallInitialGeneration(ctx context.Context, binding GenerationBinding, blob, metadata []byte) (GenerationRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{binding.KeyID}, func(memory *MemoryLifecycleStore) (GenerationRecord, error) {
		return memory.InstallInitialGeneration(ctx, binding, blob, metadata)
	})
}

// LoadCurrentGeneration implements LifecycleStore.
func (s *FileLifecycleStore) LoadCurrentGeneration(ctx context.Context, keyID string) (GenerationRecord, error) {
	return readFileLifecycleState(ctx, s, []string{keyID}, func(memory *MemoryLifecycleStore) (GenerationRecord, error) {
		return memory.LoadCurrentGeneration(ctx, keyID)
	})
}

// AcquireRunLease implements LifecycleStore.
func (s *FileLifecycleStore) AcquireRunLease(ctx context.Context, binding GenerationBinding, kind RunKind, sessionID tss.SessionID) (RunLease, error) {
	return mutateFileLifecycleState(ctx, s, []string{binding.KeyID}, func(memory *MemoryLifecycleStore) (RunLease, error) {
		return memory.AcquireRunLease(ctx, binding, kind, sessionID)
	})
}

// AcquireReshareReceiverLease implements LifecycleStore.
func (s *FileLifecycleStore) AcquireReshareReceiverLease(ctx context.Context, anchor ReshareReceiverAnchor) (RunLease, error) {
	return mutateFileLifecycleState(ctx, s, []string{anchor.Source.KeyID}, func(memory *MemoryLifecycleStore) (RunLease, error) {
		return memory.AcquireReshareReceiverLease(ctx, anchor)
	})
}

// FinishRunLease implements LifecycleStore.
func (s *FileLifecycleStore) FinishRunLease(ctx context.Context, lease RunLease, outcome RunLeaseOutcome) error {
	_, err := mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID}, func(memory *MemoryLifecycleStore) (struct{}, error) {
		return struct{}{}, memory.FinishRunLease(ctx, lease, outcome)
	})
	return err
}

// MarkProtocolRefreshFailed implements LifecycleStore.
func (s *FileLifecycleStore) MarkProtocolRefreshFailed(ctx context.Context, lease RunLease, reason string) (RefreshDisabledRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID}, func(memory *MemoryLifecycleStore) (RefreshDisabledRecord, error) {
		return memory.MarkProtocolRefreshFailed(ctx, lease, reason)
	})
}

// CommitAvailablePresignFromLease implements LifecycleStore.
func (s *FileLifecycleStore) CommitAvailablePresignFromLease(ctx context.Context, lease RunLease, presignID string, blob, metadata []byte) error {
	_, err := mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID}, func(memory *MemoryLifecycleStore) (struct{}, error) {
		return struct{}{}, memory.CommitAvailablePresignFromLease(ctx, lease, presignID, blob, metadata)
	})
	return err
}

// PreparePresignCandidate implements LifecycleStore.
func (s *FileLifecycleStore) PreparePresignCandidate(ctx context.Context, binding GenerationBinding, presignID string) (PresignCandidate, error) {
	return readFileLifecycleState(ctx, s, []string{binding.KeyID}, func(memory *MemoryLifecycleStore) (PresignCandidate, error) {
		return memory.PreparePresignCandidate(ctx, binding, presignID)
	})
}

// CommitSignAttempt implements LifecycleStore. A persistence failure is always
// returned as AttemptOutcomeUnknownError because the caller cannot infer
// whether the manifest swap became durable.
func (s *FileLifecycleStore) CommitSignAttempt(ctx context.Context, binding GenerationBinding, presignID string, intent SignAttemptIntent, exactOutbox []byte) (AttemptCommit, error) {
	commit, err := mutateFileLifecycleState(ctx, s, []string{binding.KeyID}, func(memory *MemoryLifecycleStore) (AttemptCommit, error) {
		return memory.CommitSignAttempt(ctx, binding, presignID, intent, exactOutbox)
	})
	if err == nil {
		return commit, nil
	}
	if _, ok := errors.AsType[*fileLifecyclePersistError](err); !ok {
		return AttemptCommit{}, err
	}
	return AttemptCommit{}, &AttemptOutcomeUnknownError{
		Cause: err,
		Query: AttemptQuery{
			Binding:      binding,
			PresignID:    presignID,
			AttemptID:    intent.AttemptID,
			IntentDigest: append([]byte(nil), intent.IntentDigest...),
		},
	}
}

// QueryAttemptOutcome implements LifecycleStore.
func (s *FileLifecycleStore) QueryAttemptOutcome(ctx context.Context, query AttemptQuery) (SignAttemptRecord, error) {
	return readFileLifecycleState(ctx, s, []string{query.Binding.KeyID}, func(memory *MemoryLifecycleStore) (SignAttemptRecord, error) {
		return memory.QueryAttemptOutcome(ctx, query)
	})
}

// MarkAttemptDelivered implements LifecycleStore.
func (s *FileLifecycleStore) MarkAttemptDelivered(ctx context.Context, query AttemptQuery, delivery []byte) (SignAttemptRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{query.Binding.KeyID}, func(memory *MemoryLifecycleStore) (SignAttemptRecord, error) {
		return memory.MarkAttemptDelivered(ctx, query, delivery)
	})
}

// CompleteAttempt implements LifecycleStore.
func (s *FileLifecycleStore) CompleteAttempt(ctx context.Context, query AttemptQuery, completion []byte) (SignAttemptRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{query.Binding.KeyID}, func(memory *MemoryLifecycleStore) (SignAttemptRecord, error) {
		return memory.CompleteAttempt(ctx, query, completion)
	})
}

// AbortAttempt implements LifecycleStore.
func (s *FileLifecycleStore) AbortAttempt(ctx context.Context, query AttemptQuery, reason string) (SignAttemptRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{query.Binding.KeyID}, func(memory *MemoryLifecycleStore) (SignAttemptRecord, error) {
		return memory.AbortAttempt(ctx, query, reason)
	})
}

// BurnPresign implements LifecycleStore.
func (s *FileLifecycleStore) BurnPresign(ctx context.Context, binding GenerationBinding, presignID, reason string) error {
	_, err := mutateFileLifecycleState(ctx, s, []string{binding.KeyID}, func(memory *MemoryLifecycleStore) (struct{}, error) {
		return struct{}{}, memory.BurnPresign(ctx, binding, presignID, reason)
	})
	return err
}

// BeginCutover implements LifecycleStore.
func (s *FileLifecycleStore) BeginCutover(ctx context.Context, source, target GenerationBinding) (CutoverFence, error) {
	return mutateFileLifecycleState(ctx, s, []string{source.KeyID, target.KeyID}, func(memory *MemoryLifecycleStore) (CutoverFence, error) {
		return memory.BeginCutover(ctx, source, target)
	})
}

// BeginCutoverFromLease implements LifecycleStore.
func (s *FileLifecycleStore) BeginCutoverFromLease(ctx context.Context, lease RunLease, target GenerationBinding) (CutoverFence, error) {
	return mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID, target.KeyID}, func(memory *MemoryLifecycleStore) (CutoverFence, error) {
		return memory.BeginCutoverFromLease(ctx, lease, target)
	})
}

// CommitRetirementFromLease implements LifecycleStore.
func (s *FileLifecycleStore) CommitRetirementFromLease(ctx context.Context, lease RunLease, target GenerationBinding) error {
	_, err := mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID, target.KeyID}, func(memory *MemoryLifecycleStore) (struct{}, error) {
		return struct{}{}, memory.CommitRetirementFromLease(ctx, lease, target)
	})
	return err
}

// CommitCutover implements LifecycleStore.
func (s *FileLifecycleStore) CommitCutover(ctx context.Context, fence CutoverFence, targetBlob, targetMetadata []byte) (GenerationRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{fence.Source.KeyID, fence.Target.KeyID}, func(memory *MemoryLifecycleStore) (GenerationRecord, error) {
		return memory.CommitCutover(ctx, fence, targetBlob, targetMetadata)
	})
}

// AbortCutover implements LifecycleStore.
func (s *FileLifecycleStore) AbortCutover(ctx context.Context, fence CutoverFence, reason string) error {
	_, err := mutateFileLifecycleState(ctx, s, []string{fence.Source.KeyID, fence.Target.KeyID}, func(memory *MemoryLifecycleStore) (struct{}, error) {
		return struct{}{}, memory.AbortCutover(ctx, fence, reason)
	})
	return err
}

// CommitInitialGenerationFromLease implements LifecycleStore.
func (s *FileLifecycleStore) CommitInitialGenerationFromLease(ctx context.Context, lease RunLease, child GenerationBinding, childBlob, childMetadata []byte) (GenerationRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID, child.KeyID}, func(memory *MemoryLifecycleStore) (GenerationRecord, error) {
		return memory.CommitInitialGenerationFromLease(ctx, lease, child, childBlob, childMetadata)
	})
}

// CommitInitialGenerationFromReshareLease implements LifecycleStore.
func (s *FileLifecycleStore) CommitInitialGenerationFromReshareLease(ctx context.Context, lease RunLease, target GenerationBinding, targetBlob, targetMetadata []byte) (GenerationRecord, error) {
	return mutateFileLifecycleState(ctx, s, []string{lease.Binding.KeyID, target.KeyID}, func(memory *MemoryLifecycleStore) (GenerationRecord, error) {
		return memory.CommitInitialGenerationFromReshareLease(ctx, lease, target, targetBlob, targetMetadata)
	})
}

type fileLifecyclePersistError struct {
	cause error
}

// Error reports a lifecycle transaction persistence failure without exposing
// stored secret material.
func (e *fileLifecyclePersistError) Error() string {
	if e == nil || e.cause == nil {
		return "tssrun: persist lifecycle transaction"
	}
	return "tssrun: persist lifecycle transaction: " + e.cause.Error()
}

// Unwrap returns the underlying persistence failure.
func (e *fileLifecyclePersistError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func readFileLifecycleState[T any](ctx context.Context, store *FileLifecycleStore, keyIDs []string, read func(*MemoryLifecycleStore) (T, error)) (T, error) {
	return withFileLifecycleState(ctx, store, keyIDs, false, read)
}

func mutateFileLifecycleState[T any](ctx context.Context, store *FileLifecycleStore, keyIDs []string, mutate func(*MemoryLifecycleStore) (T, error)) (T, error) {
	return withFileLifecycleState(ctx, store, keyIDs, true, mutate)
}

func withFileLifecycleState[T any](ctx context.Context, store *FileLifecycleStore, keyIDs []string, persist bool, operation func(*MemoryLifecycleStore) (T, error)) (T, error) {
	var zero T
	if store == nil || operation == nil || len(keyIDs) == 0 {
		return zero, ErrInvalidLifecycleRecord
	}
	for _, keyID := range keyIDs {
		if err := validateLifecycleIdentifier(keyID); err != nil {
			return zero, fmt.Errorf("%w: invalid key id", ErrInvalidLifecycleRecord)
		}
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return zero, ErrFileLifecycleStoreClosed
	}
	storageKeyID := fileLifecycleGlobalKeyID
	release, err := store.acquireLifecycleLocks(ctx, keyIDs)
	if err != nil {
		return zero, err
	}
	defer release()
	keyDirectory, err := store.prepareKeyDirectory(storageKeyID)
	if err != nil {
		return zero, err
	}
	memory, cache, err := loadFileLifecycleState(store, keyDirectory, storageKeyID)
	if err != nil {
		return zero, err
	}
	defer clearMemoryLifecycleState(memory)
	if err := reconcileFileLifecycleArtifacts(keyDirectory, cache); err != nil {
		return zero, err
	}
	result, err := operation(memory)
	if err != nil {
		return zero, err
	}
	if !persist {
		return result, nil
	}
	if err := persistFileLifecycleState(store, keyDirectory, storageKeyID, memory, cache); err != nil {
		return zero, &fileLifecyclePersistError{cause: err}
	}
	return result, nil
}

type fileProcessSemaphore struct {
	ch chan struct{}
}

var fileLifecycleProcessLocks sync.Map

func (s *FileLifecycleStore) acquireLifecycleLocks(ctx context.Context, keyIDs []string) (func(), error) {
	unique := make(map[string]struct{}, len(keyIDs))
	lineages := make([]string, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		lockID := "lineage:" + keyID
		if _, duplicate := unique[lockID]; duplicate {
			continue
		}
		unique[lockID] = struct{}{}
		lineages = append(lineages, lockID)
	}
	sort.Strings(lineages)
	releases := make([]func(), 0, len(lineages)+1)
	releaseAll := func() {
		for _, release := range slices.Backward(releases) {
			release()
		}
	}
	for _, lineage := range lineages {
		release, err := s.acquireKeyLock(ctx, lineage)
		if err != nil {
			releaseAll()
			return nil, err
		}
		releases = append(releases, release)
	}
	// The single manifest is the compare-and-swap object for every lineage. It
	// is acquired after the sorted lineage locks and held through load,
	// mutation, and rename, preventing distinct keys from losing updates.
	releaseManifest, err := s.acquireKeyLock(ctx, "manifest:"+fileLifecycleGlobalKeyID)
	if err != nil {
		releaseAll()
		return nil, err
	}
	releases = append(releases, releaseManifest)
	return releaseAll, nil
}

func (s *FileLifecycleStore) acquireKeyLock(ctx context.Context, keyID string) (func(), error) {
	keyHash := fileLifecycleKeyHash(keyID)
	lockPath := filepath.Join(s.directory, fileLifecycleLocksDirectory, keyHash+".lock")
	value, _ := fileLifecycleProcessLocks.LoadOrStore(lockPath, &fileProcessSemaphore{ch: make(chan struct{}, 1)})
	semaphore := value.(*fileProcessSemaphore)
	select {
	case semaphore.ch <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	processLocked := true
	defer func() {
		if processLocked {
			<-semaphore.ch
		}
	}()

	// #nosec G304 G703 -- lockPath is rooted in the constructor-validated private
	// store directory and its filename is a fixed-width SHA-256 encoding.
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle key lock: %w", err)
	}
	if err := validatePrivateLifecycleFile(file, lockPath); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := lockFileContext(ctx, file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock lifecycle key: %w", err)
	}
	processLocked = false
	return func() {
		_ = unlockFile(file)
		_ = file.Close()
		<-semaphore.ch
	}, nil
}

func (s *FileLifecycleStore) prepareKeyDirectory(keyID string) (string, error) {
	keyDirectory := filepath.Join(s.directory, fileLifecycleKeysDirectory, fileLifecycleKeyHash(keyID))
	if err := preparePrivateLifecycleDirectory(keyDirectory); err != nil {
		return "", err
	}
	if err := preparePrivateLifecycleDirectory(filepath.Join(keyDirectory, fileLifecycleBlobsDirectory)); err != nil {
		return "", err
	}
	return keyDirectory, nil
}

func (s *FileLifecycleStore) injectFault(point FileLifecycleFaultPoint) error {
	if s.faultInjector == nil {
		return nil
	}
	if err := s.faultInjector(point); err != nil {
		return fmt.Errorf("injected lifecycle crash at %s: %w", point, err)
	}
	return nil
}

func fileLifecycleKeyHash(keyID string) string {
	digest := sha256.Sum256([]byte(keyID))
	return hex.EncodeToString(digest[:])
}

func preparePrivateLifecycleDirectory(path string) error {
	// #nosec G703 -- callers pass only the constructor-resolved store root or
	// fixed descendants beneath it; every component is checked for symlinks.
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// #nosec G703 -- path is constrained as described above.
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create lifecycle store directory: %w", err)
		}
		// #nosec G703 -- path is constrained as described above.
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect lifecycle store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: lifecycle store path is not a real directory", ErrInvalidLifecycleRecord)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: lifecycle store directory is group or world accessible", ErrInvalidLifecycleRecord)
	}
	return nil
}

func validatePrivateLifecycleFile(file *os.File, path string) error {
	if file == nil {
		return ErrInvalidLifecycleRecord
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect lifecycle store file: %w", err)
	}
	// #nosec G703 -- path is a store-owned lock path beneath a private root.
	lstat, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect lifecycle store path: %w", err)
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(info, lstat) {
		return fmt.Errorf("%w: lifecycle store file is not a private regular file", ErrInvalidLifecycleRecord)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: lifecycle store file is group or world accessible", ErrInvalidLifecycleRecord)
	}
	return nil
}
