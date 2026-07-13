package tssrun

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

const (
	fileLifecycleManifestVersion = 1
	fileLifecycleMaxManifestSize = 16 << 20
	fileLifecycleMaxRecords      = 1 << 16
	fileLifecycleBlobIDBytes     = 16
)

type fileLifecycleBlobKind string

const (
	fileLifecycleBlobGeneration fileLifecycleBlobKind = "generation"
	fileLifecycleBlobMetadata   fileLifecycleBlobKind = "metadata"
	fileLifecycleBlobPresign    fileLifecycleBlobKind = "presign"
	fileLifecycleBlobOutbox     fileLifecycleBlobKind = "outbox"
	fileLifecycleBlobDelivery   fileLifecycleBlobKind = "delivery"
	fileLifecycleBlobCompletion fileLifecycleBlobKind = "completion"
)

type fileLifecycleBlobRef struct {
	Kind fileLifecycleBlobKind `json:"kind"`
	ID   string                `json:"id"`
}

func (r fileLifecycleBlobRef) empty() bool {
	return r.Kind == "" && r.ID == ""
}

func (r fileLifecycleBlobRef) validate() error {
	if r.empty() {
		return nil
	}
	if !validFileLifecycleBlobKind(r.Kind) || len(r.ID) != fileLifecycleBlobIDBytes*2 {
		return ErrLifecycleCorrupt
	}
	decoded, err := hex.DecodeString(r.ID)
	if err != nil || len(decoded) != fileLifecycleBlobIDBytes {
		return ErrLifecycleCorrupt
	}
	return nil
}

type fileLifecycleManifest struct {
	Version uint16 `json:"version"`
	KeyID   string `json:"key_id"`

	Currents         []GenerationBinding            `json:"currents"`
	Generations      []fileLifecycleGeneration      `json:"generations"`
	Leases           []RunLease                     `json:"leases"`
	LeaseEffects     []fileLifecycleLeaseEffect     `json:"lease_effects"`
	RefreshDisabled  []RefreshDisabledRecord        `json:"refresh_disabled"`
	ReshareReceivers []fileLifecycleReshareReceiver `json:"reshare_receivers"`
	Presigns         []fileLifecyclePresign         `json:"presigns"`
	Attempts         []fileLifecycleAttempt         `json:"attempts"`
	Cutovers         []fileLifecycleCutover         `json:"cutovers"`

	NextLeaseToken   uint64 `json:"next_lease_token"`
	NextCutoverToken uint64 `json:"next_cutover_token"`
}

type fileLifecycleReshareReceiver struct {
	LeaseToken uint64                `json:"lease_token"`
	Anchor     ReshareReceiverAnchor `json:"anchor"`
}

type fileLifecycleLeaseEffect struct {
	LeaseToken   uint64                `json:"lease_token"`
	Kind         storedLeaseEffectKind `json:"kind"`
	PresignID    string                `json:"presign_id,omitempty"`
	Target       GenerationBinding     `json:"target"`
	Digest       []byte                `json:"digest,omitempty"`
	Reason       string                `json:"reason,omitempty"`
	CutoverToken uint64                `json:"cutover_token,omitempty"`
}

type fileLifecycleGeneration struct {
	Binding  GenerationBinding    `json:"binding"`
	Blob     fileLifecycleBlobRef `json:"blob"`
	Metadata fileLifecycleBlobRef `json:"metadata"`
	Status   GenerationStatus     `json:"status"`
}

type fileLifecyclePresign struct {
	PresignID      string               `json:"presign_id"`
	Binding        GenerationBinding    `json:"binding"`
	Blob           fileLifecycleBlobRef `json:"blob"`
	Metadata       fileLifecycleBlobRef `json:"metadata"`
	ArtifactDigest []byte               `json:"artifact_digest"`
	State          storedPresignState   `json:"state"`
	AttemptID      string               `json:"attempt_id,omitempty"`
	Reason         string               `json:"reason,omitempty"`
}

type fileLifecycleAttempt struct {
	Binding         GenerationBinding    `json:"binding"`
	PresignID       string               `json:"presign_id"`
	Intent          SignAttemptIntent    `json:"intent"`
	PresignMetadata fileLifecycleBlobRef `json:"presign_metadata"`
	ExactOutbox     fileLifecycleBlobRef `json:"exact_outbox"`
	OutboxDigest    []byte               `json:"outbox_digest"`
	Delivery        fileLifecycleBlobRef `json:"delivery"`
	Completion      fileLifecycleBlobRef `json:"completion"`
	Delivered       bool                 `json:"delivered"`
	Completed       bool                 `json:"completed"`
	Aborted         bool                 `json:"aborted"`
	AbortReason     string               `json:"abort_reason,omitempty"`
}

type fileLifecycleCutover struct {
	Fence                CutoverFence       `json:"fence"`
	State                storedCutoverState `json:"state"`
	TargetBlobDigest     []byte             `json:"target_blob_digest,omitempty"`
	TargetMetadataDigest []byte             `json:"target_metadata_digest,omitempty"`
	Reason               string             `json:"reason,omitempty"`
}

type fileLifecycleBlobCache struct {
	byDigest   map[[sha256.Size]byte]fileLifecycleBlobRef
	referenced map[string]struct{}
}

func newFileLifecycleBlobCache() *fileLifecycleBlobCache {
	return &fileLifecycleBlobCache{
		byDigest:   make(map[[sha256.Size]byte]fileLifecycleBlobRef),
		referenced: make(map[string]struct{}),
	}
}

func loadFileLifecycleState(store *FileLifecycleStore, keyDirectory, keyID string) (*MemoryLifecycleStore, *fileLifecycleBlobCache, error) {
	manifestPath := filepath.Join(keyDirectory, fileLifecycleManifestName)
	// #nosec G703 -- manifestPath is a fixed filename beneath a hash-addressed,
	// constructor-validated private key directory.
	info, err := os.Lstat(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return NewMemoryLifecycleStore(), newFileLifecycleBlobCache(), nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("inspect lifecycle manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("%w: invalid lifecycle manifest file", ErrLifecycleCorrupt)
	}
	if info.Size() <= 0 || info.Size() > fileLifecycleMaxManifestSize {
		return nil, nil, fmt.Errorf("%w: invalid lifecycle manifest size", ErrLifecycleCorrupt)
	}
	// #nosec G304 G703 -- manifestPath is constrained as described above.
	encrypted, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read lifecycle manifest: %w", err)
	}
	if len(encrypted) == 0 || len(encrypted) > fileLifecycleMaxManifestSize {
		return nil, nil, fmt.Errorf("%w: invalid lifecycle manifest size", ErrLifecycleCorrupt)
	}
	plaintext, err := tss.DecryptSignAttemptWithPassphrase(encrypted, store.passphrase, fileLifecycleManifestAAD(keyID))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decrypt lifecycle manifest: %w", ErrLifecycleCorrupt, err)
	}
	defer clearBytes(plaintext)
	manifest, err := decodeFileLifecycleManifest(plaintext)
	if err != nil {
		return nil, nil, err
	}
	if manifest.Version != fileLifecycleManifestVersion || manifest.KeyID != keyID {
		return nil, nil, fmt.Errorf("%w: lifecycle manifest identity mismatch", ErrLifecycleCorrupt)
	}
	if exceedsFileLifecycleRecordLimits(manifest) {
		return nil, nil, fmt.Errorf("%w: lifecycle manifest record limit exceeded", ErrLifecycleCorrupt)
	}

	memory := NewMemoryLifecycleStore()
	cache := newFileLifecycleBlobCache()
	for _, current := range manifest.Currents {
		if _, duplicate := memory.current[current.KeyID]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate current generation", ErrLifecycleCorrupt)
		}
		memory.current[current.KeyID] = current
	}
	for _, generation := range manifest.Generations {
		blob, err := loadFileLifecycleBlob(store, keyDirectory, keyID, generation.Blob, cache)
		if err != nil {
			clearMemoryLifecycleState(memory)
			return nil, nil, err
		}
		metadata, err := loadFileLifecycleBlob(store, keyDirectory, keyID, generation.Metadata, cache)
		if err != nil {
			clearBytes(blob)
			clearMemoryLifecycleState(memory)
			return nil, nil, err
		}
		if _, duplicate := memory.generations[generation.Binding]; duplicate {
			clearBytes(blob)
			clearBytes(metadata)
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate generation", ErrLifecycleCorrupt)
		}
		memory.generations[generation.Binding] = &storedGeneration{record: GenerationRecord{
			Binding:  generation.Binding,
			Blob:     blob,
			Metadata: metadata,
			Status:   generation.Status,
		}}
	}
	for _, lease := range manifest.Leases {
		if _, duplicate := memory.leasesByToken[lease.Token]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate lease token", ErrLifecycleCorrupt)
		}
		if _, duplicate := memory.leaseBySession[lease.SessionID]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate lease session", ErrLifecycleCorrupt)
		}
		memory.leasesByToken[lease.Token] = &storedRunLease{lease: lease}
		memory.leaseBySession[lease.SessionID] = lease.Token
	}
	for _, receiver := range manifest.ReshareReceivers {
		if _, duplicate := memory.reshareReceivers[receiver.LeaseToken]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate reshare receiver anchor", ErrLifecycleCorrupt)
		}
		memory.reshareReceivers[receiver.LeaseToken] = receiver.Anchor.Clone()
	}
	for _, effect := range manifest.LeaseEffects {
		if _, duplicate := memory.leaseEffects[effect.LeaseToken]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate lease effect", ErrLifecycleCorrupt)
		}
		memory.leaseEffects[effect.LeaseToken] = &storedLeaseEffect{
			LeaseToken: effect.LeaseToken, Kind: effect.Kind, PresignID: effect.PresignID,
			Target: effect.Target, Digest: bytes.Clone(effect.Digest), Reason: effect.Reason, CutoverToken: effect.CutoverToken,
		}
	}
	for _, disabled := range manifest.RefreshDisabled {
		if _, duplicate := memory.refreshDisabled[disabled.KeyID]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate refresh-disabled lineage", ErrLifecycleCorrupt)
		}
		memory.refreshDisabled[disabled.KeyID] = disabled.Clone()
	}
	for _, presign := range manifest.Presigns {
		blob, err := loadFileLifecycleBlob(store, keyDirectory, keyID, presign.Blob, cache)
		if err != nil {
			clearMemoryLifecycleState(memory)
			return nil, nil, err
		}
		metadata, err := loadFileLifecycleBlob(store, keyDirectory, keyID, presign.Metadata, cache)
		if err != nil {
			clearBytes(blob)
			clearMemoryLifecycleState(memory)
			return nil, nil, err
		}
		if _, duplicate := memory.presigns[presign.PresignID]; duplicate {
			clearBytes(blob)
			clearBytes(metadata)
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate presign", ErrLifecycleCorrupt)
		}
		memory.presigns[presign.PresignID] = &storedPresign{
			binding:        presign.Binding,
			blob:           blob,
			metadata:       metadata,
			artifactDigest: bytes.Clone(presign.ArtifactDigest),
			state:          presign.State,
			attemptID:      presign.AttemptID,
			reason:         presign.Reason,
		}
	}
	for _, attempt := range manifest.Attempts {
		record, err := loadFileLifecycleAttempt(store, keyDirectory, keyID, attempt, cache)
		if err != nil {
			clearMemoryLifecycleState(memory)
			return nil, nil, err
		}
		if _, duplicate := memory.attempts[record.Intent.AttemptID]; duplicate {
			clearSignAttemptRecord(&record)
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate attempt", ErrLifecycleCorrupt)
		}
		memory.attempts[record.Intent.AttemptID] = &storedAttempt{record: record}
	}
	for _, cutover := range manifest.Cutovers {
		if _, duplicate := memory.cutoversByToken[cutover.Fence.Token]; duplicate {
			clearMemoryLifecycleState(memory)
			return nil, nil, fmt.Errorf("%w: duplicate cutover", ErrLifecycleCorrupt)
		}
		stored := &storedCutover{
			fence:                cutover.Fence,
			state:                cutover.State,
			targetBlobDigest:     bytes.Clone(cutover.TargetBlobDigest),
			targetMetadataDigest: bytes.Clone(cutover.TargetMetadataDigest),
			reason:               cutover.Reason,
		}
		memory.cutoversByToken[cutover.Fence.Token] = stored
		if cutover.State == storedCutoverActive {
			cutoverKeyID := cutover.Fence.Source.KeyID
			if _, duplicate := memory.cutoverByKey[cutoverKeyID]; duplicate {
				clearMemoryLifecycleState(memory)
				return nil, nil, fmt.Errorf("%w: duplicate active cutover", ErrLifecycleCorrupt)
			}
			memory.cutoverByKey[cutoverKeyID] = cutover.Fence.Token
		}
	}
	memory.nextLeaseToken = manifest.NextLeaseToken
	memory.nextCutoverToken = manifest.NextCutoverToken
	if err := validateMemoryLifecycleStateForKey(memory, keyID); err != nil {
		clearMemoryLifecycleState(memory)
		return nil, nil, err
	}
	return memory, cache, nil
}

func persistFileLifecycleState(store *FileLifecycleStore, keyDirectory, keyID string, memory *MemoryLifecycleStore, cache *fileLifecycleBlobCache) error {
	if err := validateMemoryLifecycleStateForKey(memory, keyID); err != nil {
		return err
	}
	writer := fileLifecycleBlobWriter{
		store:        store,
		keyDirectory: keyDirectory,
		keyID:        keyID,
		cache:        cache,
	}
	manifest, err := buildFileLifecycleManifest(memory, keyID, &writer)
	if err != nil {
		return writer.rollback(err)
	}
	if writer.wroteBlob {
		if err := syncLifecycleDirectory(filepath.Join(keyDirectory, fileLifecycleBlobsDirectory)); err != nil {
			return writer.rollback(fmt.Errorf("sync lifecycle blob directory: %w", err))
		}
	}
	plaintext, err := json.Marshal(manifest)
	if err != nil {
		return writer.rollback(fmt.Errorf("encode lifecycle manifest: %w", err))
	}
	defer clearBytes(plaintext)
	if len(plaintext) == 0 || len(plaintext) > fileLifecycleMaxManifestSize/2 {
		return writer.rollback(fmt.Errorf("%w: lifecycle manifest plaintext too large", ErrInvalidLifecycleRecord))
	}
	encrypted, err := tss.EncryptSignAttemptWithPassphrase(plaintext, store.passphrase, fileLifecycleManifestAAD(keyID), &store.params)
	if err != nil {
		return writer.rollback(fmt.Errorf("encrypt lifecycle manifest: %w", err))
	}
	defer clearBytes(encrypted)
	if len(encrypted) > fileLifecycleMaxManifestSize {
		return writer.rollback(fmt.Errorf("%w: lifecycle manifest ciphertext too large", ErrInvalidLifecycleRecord))
	}
	renamed, err := replaceFileLifecycleManifest(store, keyDirectory, encrypted)
	if err != nil && !renamed {
		return writer.rollback(err)
	}
	return err
}

func buildFileLifecycleManifest(memory *MemoryLifecycleStore, keyID string, writer *fileLifecycleBlobWriter) (fileLifecycleManifest, error) {
	manifest := fileLifecycleManifest{
		Version:          fileLifecycleManifestVersion,
		KeyID:            keyID,
		NextLeaseToken:   memory.nextLeaseToken,
		NextCutoverToken: memory.nextCutoverToken,
		Currents:         make([]GenerationBinding, 0, len(memory.current)),
		Generations:      make([]fileLifecycleGeneration, 0, len(memory.generations)),
		Leases:           make([]RunLease, 0, len(memory.leasesByToken)),
		LeaseEffects:     make([]fileLifecycleLeaseEffect, 0, len(memory.leaseEffects)),
		RefreshDisabled:  make([]RefreshDisabledRecord, 0, len(memory.refreshDisabled)),
		ReshareReceivers: make([]fileLifecycleReshareReceiver, 0, len(memory.reshareReceivers)),
		Presigns:         make([]fileLifecyclePresign, 0, len(memory.presigns)),
		Attempts:         make([]fileLifecycleAttempt, 0, len(memory.attempts)),
		Cutovers:         make([]fileLifecycleCutover, 0, len(memory.cutoversByToken)),
	}
	for _, disabled := range memory.refreshDisabled {
		manifest.RefreshDisabled = append(manifest.RefreshDisabled, disabled.Clone())
	}
	for _, current := range memory.current {
		manifest.Currents = append(manifest.Currents, current)
	}
	for binding, stored := range memory.generations {
		blob, err := writer.storeBlob(fileLifecycleBlobGeneration, stored.record.Blob)
		if err != nil {
			return fileLifecycleManifest{}, err
		}
		metadata, err := writer.storeBlob(fileLifecycleBlobMetadata, stored.record.Metadata)
		if err != nil {
			return fileLifecycleManifest{}, err
		}
		manifest.Generations = append(manifest.Generations, fileLifecycleGeneration{
			Binding:  binding,
			Blob:     blob,
			Metadata: metadata,
			Status:   stored.record.Status,
		})
	}
	for _, stored := range memory.leasesByToken {
		manifest.Leases = append(manifest.Leases, stored.lease)
	}
	for _, effect := range memory.leaseEffects {
		manifest.LeaseEffects = append(manifest.LeaseEffects, fileLifecycleLeaseEffect{
			LeaseToken: effect.LeaseToken, Kind: effect.Kind, PresignID: effect.PresignID,
			Target: effect.Target, Digest: bytes.Clone(effect.Digest), Reason: effect.Reason, CutoverToken: effect.CutoverToken,
		})
	}
	for leaseToken, anchor := range memory.reshareReceivers {
		manifest.ReshareReceivers = append(manifest.ReshareReceivers, fileLifecycleReshareReceiver{
			LeaseToken: leaseToken,
			Anchor:     anchor.Clone(),
		})
	}
	for presignID, stored := range memory.presigns {
		blob, err := writer.storeBlob(fileLifecycleBlobPresign, stored.blob)
		if err != nil {
			return fileLifecycleManifest{}, err
		}
		metadata, err := writer.storeBlob(fileLifecycleBlobMetadata, stored.metadata)
		if err != nil {
			return fileLifecycleManifest{}, err
		}
		manifest.Presigns = append(manifest.Presigns, fileLifecyclePresign{
			PresignID:      presignID,
			Binding:        stored.binding,
			Blob:           blob,
			Metadata:       metadata,
			ArtifactDigest: bytes.Clone(stored.artifactDigest),
			State:          stored.state,
			AttemptID:      stored.attemptID,
			Reason:         stored.reason,
		})
	}
	for _, stored := range memory.attempts {
		attempt, err := writer.storeAttempt(stored.record)
		if err != nil {
			return fileLifecycleManifest{}, err
		}
		manifest.Attempts = append(manifest.Attempts, attempt)
	}
	for _, stored := range memory.cutoversByToken {
		manifest.Cutovers = append(manifest.Cutovers, fileLifecycleCutover{
			Fence:                stored.fence,
			State:                stored.state,
			TargetBlobDigest:     bytes.Clone(stored.targetBlobDigest),
			TargetMetadataDigest: bytes.Clone(stored.targetMetadataDigest),
			Reason:               stored.reason,
		})
	}
	sort.Slice(manifest.Generations, func(i, j int) bool {
		a := manifest.Generations[i].Binding
		b := manifest.Generations[j].Binding
		if a.KeyID != b.KeyID {
			return a.KeyID < b.KeyID
		}
		if a.KeyGeneration != b.KeyGeneration {
			return a.KeyGeneration < b.KeyGeneration
		}
		return bytes.Compare(a.EpochID[:], b.EpochID[:]) < 0
	})
	sort.Slice(manifest.Currents, func(i, j int) bool { return manifest.Currents[i].KeyID < manifest.Currents[j].KeyID })
	sort.Slice(manifest.RefreshDisabled, func(i, j int) bool { return manifest.RefreshDisabled[i].KeyID < manifest.RefreshDisabled[j].KeyID })
	sort.Slice(manifest.Leases, func(i, j int) bool { return manifest.Leases[i].Token < manifest.Leases[j].Token })
	sort.Slice(manifest.LeaseEffects, func(i, j int) bool { return manifest.LeaseEffects[i].LeaseToken < manifest.LeaseEffects[j].LeaseToken })
	sort.Slice(manifest.ReshareReceivers, func(i, j int) bool {
		return manifest.ReshareReceivers[i].LeaseToken < manifest.ReshareReceivers[j].LeaseToken
	})
	sort.Slice(manifest.Presigns, func(i, j int) bool { return manifest.Presigns[i].PresignID < manifest.Presigns[j].PresignID })
	sort.Slice(manifest.Attempts, func(i, j int) bool {
		return manifest.Attempts[i].Intent.AttemptID < manifest.Attempts[j].Intent.AttemptID
	})
	sort.Slice(manifest.Cutovers, func(i, j int) bool { return manifest.Cutovers[i].Fence.Token < manifest.Cutovers[j].Fence.Token })
	return manifest, nil
}

type fileLifecycleBlobWriter struct {
	store        *FileLifecycleStore
	keyDirectory string
	keyID        string
	cache        *fileLifecycleBlobCache
	wroteBlob    bool
	newBlobPaths []string
}

func (w *fileLifecycleBlobWriter) rollback(cause error) error {
	if w == nil || len(w.newBlobPaths) == 0 {
		return cause
	}
	var cleanupErrors []error
	for _, path := range w.newBlobPaths {
		// #nosec G703 -- paths are freshly generated fixed-width blob paths
		// beneath the validated private blob directory.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove uncommitted lifecycle blob: %w", err))
		}
	}
	if err := syncLifecycleDirectory(filepath.Join(w.keyDirectory, fileLifecycleBlobsDirectory)); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("sync lifecycle blob rollback: %w", err))
	}
	if len(cleanupErrors) == 0 {
		return cause
	}
	return errors.Join(append([]error{cause}, cleanupErrors...)...)
}

func (w *fileLifecycleBlobWriter) storeAttempt(record SignAttemptRecord) (fileLifecycleAttempt, error) {
	presignMetadata, err := w.storeBlob(fileLifecycleBlobMetadata, record.PresignMetadata)
	if err != nil {
		return fileLifecycleAttempt{}, err
	}
	exactOutbox, err := w.storeBlob(fileLifecycleBlobOutbox, record.ExactOutbox)
	if err != nil {
		return fileLifecycleAttempt{}, err
	}
	delivery, err := w.storeBlob(fileLifecycleBlobDelivery, record.Delivery)
	if err != nil {
		return fileLifecycleAttempt{}, err
	}
	completion, err := w.storeBlob(fileLifecycleBlobCompletion, record.Completion)
	if err != nil {
		return fileLifecycleAttempt{}, err
	}
	return fileLifecycleAttempt{
		Binding:         record.Binding,
		PresignID:       record.PresignID,
		Intent:          record.Intent.Clone(),
		PresignMetadata: presignMetadata,
		ExactOutbox:     exactOutbox,
		OutboxDigest:    bytes.Clone(record.OutboxDigest),
		Delivery:        delivery,
		Completion:      completion,
		Delivered:       record.Delivered,
		Completed:       record.Completed,
		Aborted:         record.Aborted,
		AbortReason:     record.AbortReason,
	}, nil
}

func (w *fileLifecycleBlobWriter) storeBlob(kind fileLifecycleBlobKind, plaintext []byte) (fileLifecycleBlobRef, error) {
	if len(plaintext) == 0 {
		return fileLifecycleBlobRef{}, nil
	}
	if err := validateLifecycleBlob(plaintext, true); err != nil {
		return fileLifecycleBlobRef{}, err
	}
	digest := fileLifecycleBlobCacheKey(kind, plaintext)
	if ref, ok := w.cache.byDigest[digest]; ok {
		return ref, nil
	}
	ref, err := writeImmutableFileLifecycleBlob(w.store, w.keyDirectory, w.keyID, kind, plaintext)
	if err != nil {
		return fileLifecycleBlobRef{}, err
	}
	w.cache.byDigest[digest] = ref
	w.cache.referenced[ref.ID] = struct{}{}
	w.wroteBlob = true
	w.newBlobPaths = append(w.newBlobPaths, filepath.Join(w.keyDirectory, fileLifecycleBlobsDirectory, ref.ID+".enc"))
	return ref, nil
}

func loadFileLifecycleAttempt(store *FileLifecycleStore, keyDirectory, keyID string, attempt fileLifecycleAttempt, cache *fileLifecycleBlobCache) (SignAttemptRecord, error) {
	presignMetadata, err := loadFileLifecycleBlob(store, keyDirectory, keyID, attempt.PresignMetadata, cache)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	exactOutbox, err := loadFileLifecycleBlob(store, keyDirectory, keyID, attempt.ExactOutbox, cache)
	if err != nil {
		clearBytes(presignMetadata)
		return SignAttemptRecord{}, err
	}
	delivery, err := loadFileLifecycleBlob(store, keyDirectory, keyID, attempt.Delivery, cache)
	if err != nil {
		clearBytes(presignMetadata)
		clearBytes(exactOutbox)
		return SignAttemptRecord{}, err
	}
	completion, err := loadFileLifecycleBlob(store, keyDirectory, keyID, attempt.Completion, cache)
	if err != nil {
		clearBytes(presignMetadata)
		clearBytes(exactOutbox)
		clearBytes(delivery)
		return SignAttemptRecord{}, err
	}
	return SignAttemptRecord{
		Binding:         attempt.Binding,
		PresignID:       attempt.PresignID,
		Intent:          attempt.Intent.Clone(),
		PresignMetadata: presignMetadata,
		ExactOutbox:     exactOutbox,
		OutboxDigest:    bytes.Clone(attempt.OutboxDigest),
		Delivery:        delivery,
		Completion:      completion,
		Delivered:       attempt.Delivered,
		Completed:       attempt.Completed,
		Aborted:         attempt.Aborted,
		AbortReason:     attempt.AbortReason,
	}, nil
}

func loadFileLifecycleBlob(store *FileLifecycleStore, keyDirectory, keyID string, ref fileLifecycleBlobRef, cache *fileLifecycleBlobCache) ([]byte, error) {
	if err := ref.validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid lifecycle blob reference", ErrLifecycleCorrupt)
	}
	if ref.empty() {
		return nil, nil
	}
	cache.referenced[ref.ID] = struct{}{}
	path := filepath.Join(keyDirectory, fileLifecycleBlobsDirectory, ref.ID+".enc")
	// #nosec G703 -- path uses a validated fixed-width hexadecimal blob ID
	// beneath the constructor-validated private key directory.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect lifecycle blob: %w", ErrLifecycleCorrupt, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxLifecycleBlobBytes+4096 {
		return nil, fmt.Errorf("%w: invalid lifecycle blob file", ErrLifecycleCorrupt)
	}
	// #nosec G304 G703 -- path is constrained as described above.
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read lifecycle blob: %w", ErrLifecycleCorrupt, err)
	}
	if len(encrypted) == 0 || len(encrypted) > maxLifecycleBlobBytes+4096 {
		return nil, fmt.Errorf("%w: invalid lifecycle blob size", ErrLifecycleCorrupt)
	}
	plaintext, err := decryptFileLifecycleBlob(store, keyID, ref, encrypted)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt lifecycle blob: %w", ErrLifecycleCorrupt, err)
	}
	if err := validateLifecycleBlob(plaintext, true); err != nil {
		clearBytes(plaintext)
		return nil, fmt.Errorf("%w: invalid lifecycle blob plaintext", ErrLifecycleCorrupt)
	}
	cache.byDigest[fileLifecycleBlobCacheKey(ref.Kind, plaintext)] = ref
	return plaintext, nil
}

func reconcileFileLifecycleArtifacts(keyDirectory string, cache *fileLifecycleBlobCache) error {
	blobsDirectory := filepath.Join(keyDirectory, fileLifecycleBlobsDirectory)
	entries, err := os.ReadDir(blobsDirectory)
	if err != nil {
		return fmt.Errorf("inspect lifecycle blob directory: %w", err)
	}
	removedBlobs := false
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != fileLifecycleBlobIDBytes*2+len(".enc") || !strings.HasSuffix(name, ".enc") {
			return fmt.Errorf("%w: unexpected lifecycle blob artifact", ErrLifecycleCorrupt)
		}
		identifier := strings.TrimSuffix(name, ".enc")
		decoded, decodeErr := hex.DecodeString(identifier)
		if decodeErr != nil || len(decoded) != fileLifecycleBlobIDBytes {
			return fmt.Errorf("%w: invalid lifecycle blob artifact", ErrLifecycleCorrupt)
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("inspect lifecycle blob artifact: %w", infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: invalid lifecycle blob artifact", ErrLifecycleCorrupt)
		}
		if _, referenced := cache.referenced[identifier]; referenced {
			continue
		}
		path := filepath.Join(blobsDirectory, name)
		// #nosec G703 -- identifier is validated fixed-width hexadecimal and the
		// path is beneath the constructor-validated private blob directory.
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove orphan lifecycle blob: %w", err)
		}
		removedBlobs = true
	}
	if removedBlobs {
		if err := syncLifecycleDirectory(blobsDirectory); err != nil {
			return fmt.Errorf("sync orphan lifecycle blob recovery: %w", err)
		}
	}

	keyEntries, err := os.ReadDir(keyDirectory)
	if err != nil {
		return fmt.Errorf("inspect lifecycle key directory: %w", err)
	}
	removedTemporary := false
	for _, entry := range keyEntries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".manifest-") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("inspect stale lifecycle manifest replacement: %w", infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: invalid stale lifecycle manifest replacement", ErrLifecycleCorrupt)
		}
		path := filepath.Join(keyDirectory, name)
		// #nosec G703 -- name is a store-owned manifest temporary filename
		// returned by os.CreateTemp beneath the validated key directory.
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale lifecycle manifest replacement: %w", err)
		}
		removedTemporary = true
	}
	if removedTemporary {
		if err := syncLifecycleDirectory(keyDirectory); err != nil {
			return fmt.Errorf("sync stale lifecycle manifest recovery: %w", err)
		}
	}
	return nil
}

func writeImmutableFileLifecycleBlob(store *FileLifecycleStore, keyDirectory, keyID string, kind fileLifecycleBlobKind, plaintext []byte) (fileLifecycleBlobRef, error) {
	for range 8 {
		identifier := make([]byte, fileLifecycleBlobIDBytes)
		if _, err := io.ReadFull(rand.Reader, identifier); err != nil {
			return fileLifecycleBlobRef{}, fmt.Errorf("generate lifecycle blob id: %w", err)
		}
		ref := fileLifecycleBlobRef{Kind: kind, ID: hex.EncodeToString(identifier)}
		encrypted, err := encryptFileLifecycleBlob(store, keyID, ref, plaintext)
		if err != nil {
			return fileLifecycleBlobRef{}, err
		}
		path := filepath.Join(keyDirectory, fileLifecycleBlobsDirectory, ref.ID+".enc")
		// #nosec G304 -- path uses a freshly generated fixed-width hexadecimal
		// identifier beneath the validated private blob directory.
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			clearBytes(encrypted)
			continue
		}
		if err != nil {
			clearBytes(encrypted)
			return fileLifecycleBlobRef{}, fmt.Errorf("create lifecycle blob: %w", err)
		}
		remove := true
		defer func() {
			_ = file.Close()
			if remove {
				// #nosec G703 -- path is the constrained blob path created above.
				_ = os.Remove(path)
			}
			clearBytes(encrypted)
		}()
		if err := writeLifecycleFile(file, encrypted); err != nil {
			return fileLifecycleBlobRef{}, fmt.Errorf("write lifecycle blob: %w", err)
		}
		if err := store.injectFault(FileLifecycleFaultAfterBlobWrite); err != nil {
			return fileLifecycleBlobRef{}, err
		}
		if err := file.Sync(); err != nil {
			return fileLifecycleBlobRef{}, fmt.Errorf("fsync lifecycle blob: %w", err)
		}
		if err := store.injectFault(FileLifecycleFaultAfterBlobSync); err != nil {
			return fileLifecycleBlobRef{}, err
		}
		if err := file.Close(); err != nil {
			return fileLifecycleBlobRef{}, fmt.Errorf("close lifecycle blob: %w", err)
		}
		remove = false
		return ref, nil
	}
	return fileLifecycleBlobRef{}, errors.New("tssrun: lifecycle blob id collisions exhausted")
}

func encryptFileLifecycleBlob(store *FileLifecycleStore, keyID string, ref fileLifecycleBlobRef, plaintext []byte) ([]byte, error) {
	aad := fileLifecycleBlobAAD(keyID, ref)
	switch ref.Kind {
	case fileLifecycleBlobGeneration:
		return tss.EncryptKeyShareWithPassphrase(plaintext, store.passphrase, aad, &store.params)
	case fileLifecycleBlobPresign:
		return tss.EncryptPresignWithPassphrase(plaintext, store.passphrase, aad, &store.params)
	case fileLifecycleBlobMetadata, fileLifecycleBlobOutbox, fileLifecycleBlobDelivery, fileLifecycleBlobCompletion:
		return tss.EncryptSignAttemptWithPassphrase(plaintext, store.passphrase, aad, &store.params)
	default:
		return nil, ErrInvalidLifecycleRecord
	}
}

func decryptFileLifecycleBlob(store *FileLifecycleStore, keyID string, ref fileLifecycleBlobRef, encrypted []byte) ([]byte, error) {
	aad := fileLifecycleBlobAAD(keyID, ref)
	switch ref.Kind {
	case fileLifecycleBlobGeneration:
		return tss.DecryptKeyShareWithPassphrase(encrypted, store.passphrase, aad)
	case fileLifecycleBlobPresign:
		return tss.DecryptPresignWithPassphrase(encrypted, store.passphrase, aad)
	case fileLifecycleBlobMetadata, fileLifecycleBlobOutbox, fileLifecycleBlobDelivery, fileLifecycleBlobCompletion:
		return tss.DecryptSignAttemptWithPassphrase(encrypted, store.passphrase, aad)
	default:
		return nil, ErrLifecycleCorrupt
	}
}

func replaceFileLifecycleManifest(store *FileLifecycleStore, keyDirectory string, encrypted []byte) (bool, error) {
	temporary, err := os.CreateTemp(keyDirectory, ".manifest-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create lifecycle manifest replacement: %w", err)
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			// #nosec G703 -- temporaryPath was returned by os.CreateTemp in the
			// validated private key directory.
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, fmt.Errorf("restrict lifecycle manifest replacement: %w", err)
	}
	if err := writeLifecycleFile(temporary, encrypted); err != nil {
		return false, fmt.Errorf("write lifecycle manifest replacement: %w", err)
	}
	if err := store.injectFault(FileLifecycleFaultAfterManifestWrite); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("fsync lifecycle manifest replacement: %w", err)
	}
	if err := store.injectFault(FileLifecycleFaultAfterManifestSync); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close lifecycle manifest replacement: %w", err)
	}
	manifestPath := filepath.Join(keyDirectory, fileLifecycleManifestName)
	// #nosec G703 -- both paths are within the validated private key directory;
	// temporaryPath was returned by os.CreateTemp and manifestPath is fixed.
	if err := os.Rename(temporaryPath, manifestPath); err != nil {
		return false, fmt.Errorf("replace lifecycle manifest: %w", err)
	}
	remove = false
	if err := store.injectFault(FileLifecycleFaultAfterManifestRename); err != nil {
		return true, err
	}
	if err := syncLifecycleDirectory(keyDirectory); err != nil {
		return true, fmt.Errorf("fsync lifecycle key directory: %w", err)
	}
	if err := store.injectFault(FileLifecycleFaultAfterManifestDirectorySync); err != nil {
		return true, err
	}
	return true, nil
}

func decodeFileLifecycleManifest(encoded []byte) (fileLifecycleManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest fileLifecycleManifest
	if err := decoder.Decode(&manifest); err != nil {
		return fileLifecycleManifest{}, fmt.Errorf("%w: decode lifecycle manifest: %w", ErrLifecycleCorrupt, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fileLifecycleManifest{}, fmt.Errorf("%w: trailing lifecycle manifest data", ErrLifecycleCorrupt)
	}
	return manifest, nil
}

func validateMemoryLifecycleStateForKey(memory *MemoryLifecycleStore, keyID string) error {
	if memory == nil || keyID != fileLifecycleGlobalKeyID {
		return ErrLifecycleCorrupt
	}
	currentCounts := make(map[string]int, len(memory.current))
	for indexedKeyID, binding := range memory.current {
		if indexedKeyID != binding.KeyID || binding.Validate() != nil {
			return fmt.Errorf("%w: invalid current generation index", ErrLifecycleCorrupt)
		}
	}
	for binding, generation := range memory.generations {
		if binding.Validate() != nil || generation == nil || generation.record.Binding != binding {
			return fmt.Errorf("%w: invalid generation record", ErrLifecycleCorrupt)
		}
		if generation.record.Status != GenerationCurrent && generation.record.Status != GenerationRetired {
			return fmt.Errorf("%w: invalid generation status", ErrLifecycleCorrupt)
		}
		if generation.record.Status == GenerationCurrent {
			currentCounts[binding.KeyID]++
			if current, ok := memory.current[binding.KeyID]; !ok || current != binding || len(generation.record.Blob) == 0 {
				return fmt.Errorf("%w: current generation mismatch", ErrLifecycleCorrupt)
			}
		} else if len(generation.record.Blob) != 0 || len(generation.record.Metadata) != 0 {
			return fmt.Errorf("%w: retired generation retained secret blob", ErrLifecycleCorrupt)
		}
	}
	for indexedKeyID := range memory.current {
		if currentCounts[indexedKeyID] != 1 {
			return fmt.Errorf("%w: invalid current generation count", ErrLifecycleCorrupt)
		}
	}
	if len(memory.leasesByToken) != len(memory.leaseBySession) {
		return fmt.Errorf("%w: lease index mismatch", ErrLifecycleCorrupt)
	}
	activeLeaseCounts := make(map[string]int)
	hasActiveExclusiveLease := make(map[string]bool)
	validatedReceiverAnchors := 0
	for token, stored := range memory.leasesByToken {
		if stored == nil || stored.lease.Token != token || validateRunLease(stored.lease) != nil || token > memory.nextLeaseToken {
			return fmt.Errorf("%w: invalid run lease", ErrLifecycleCorrupt)
		}
		if memory.leaseBySession[stored.lease.SessionID] != token {
			return fmt.Errorf("%w: lease session index mismatch", ErrLifecycleCorrupt)
		}
		if stored.lease.State != RunLeaseActive && stored.lease.State != RunLeaseCompleted && stored.lease.State != RunLeaseAborted {
			return fmt.Errorf("%w: invalid run lease state", ErrLifecycleCorrupt)
		}
		receiverAnchor, receiverJoin := memory.reshareReceivers[token]
		if stored.lease.State != RunLeaseActive {
			if receiverJoin {
				return fmt.Errorf("%w: terminal lease retained reshare receiver anchor", ErrLifecycleCorrupt)
			}
			continue
		}
		leaseKeyID := stored.lease.Binding.KeyID
		activeLeaseCounts[leaseKeyID]++
		if receiverJoin {
			validatedReceiverAnchors++
			if receiverAnchor.Validate() != nil || stored.lease.Kind != RunReshare ||
				receiverAnchor.Source != stored.lease.Binding || receiverAnchor.SessionID != stored.lease.SessionID {
				return fmt.Errorf("%w: invalid reshare receiver anchor", ErrLifecycleCorrupt)
			}
			if _, hasCurrent := memory.current[leaseKeyID]; hasCurrent ||
				memory.hasKeyGenerationLocked(leaseKeyID, receiverAnchor.TargetKeyGeneration) ||
				memory.hasNonTerminalAttemptForKeyLocked(leaseKeyID) {
				return fmt.Errorf("%w: reshare receiver anchor conflicts with local state", ErrLifecycleCorrupt)
			}
			if _, fenced := memory.cutoverByKey[leaseKeyID]; fenced {
				return fmt.Errorf("%w: reshare receiver anchor overlaps cutover", ErrLifecycleCorrupt)
			}
		} else if stored.lease.Kind == RunKeygen {
			if _, hasCurrent := memory.current[leaseKeyID]; hasCurrent || memory.hasGenerationForKeyLocked(leaseKeyID) {
				return fmt.Errorf("%w: active keygen lease has generation state", ErrLifecycleCorrupt)
			}
		} else if !memory.isCurrentLocked(stored.lease.Binding) {
			return fmt.Errorf("%w: active lease is not bound to current generation", ErrLifecycleCorrupt)
		}
		if exclusiveLeaseRunKind(stored.lease.Kind) {
			hasActiveExclusiveLease[leaseKeyID] = true
		}
	}
	if validatedReceiverAnchors != len(memory.reshareReceivers) {
		return fmt.Errorf("%w: reshare receiver anchor missing active lease", ErrLifecycleCorrupt)
	}
	for leaseKeyID := range hasActiveExclusiveLease {
		if activeLeaseCounts[leaseKeyID] != 1 {
			return fmt.Errorf("%w: active exclusive lease overlaps another lease", ErrLifecycleCorrupt)
		}
	}
	for token, effect := range memory.leaseEffects {
		lease := memory.leasesByToken[token]
		if effect == nil || effect.LeaseToken != token || lease == nil || lease.lease.State == RunLeaseActive {
			return fmt.Errorf("%w: invalid lease effect", ErrLifecycleCorrupt)
		}
		switch effect.Kind {
		case storedLeaseEffectPresign:
			if lease.lease.Kind != RunPresign || lease.lease.State != RunLeaseCompleted ||
				validateLifecycleIdentifier(effect.PresignID) != nil || len(effect.Digest) != sha256.Size || memory.presigns[effect.PresignID] == nil {
				return fmt.Errorf("%w: invalid presign lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectCutover:
			cutover := memory.cutoversByToken[effect.CutoverToken]
			if !cutoverLeaseRunKind(lease.lease.Kind) || lease.lease.State != RunLeaseCompleted ||
				effect.Target.KeyID != lease.lease.Binding.KeyID || cutover == nil || cutover.fence.Source != lease.lease.Binding || cutover.fence.Target != effect.Target {
				return fmt.Errorf("%w: invalid cutover lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectRefreshFailed:
			disabled, ok := memory.refreshDisabled[lease.lease.Binding.KeyID]
			if lease.lease.Kind != RunRefresh || lease.lease.State != RunLeaseAborted ||
				!ok || disabled.SessionID != lease.lease.SessionID || disabled.Reason != effect.Reason {
				return fmt.Errorf("%w: invalid refresh-failed lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectChildGeneration:
			child := memory.generations[effect.Target]
			if lease.lease.Kind != RunChildDerivation || lease.lease.State != RunLeaseCompleted ||
				effect.Target.KeyID == lease.lease.Binding.KeyID || effect.Target.EpochID == lease.lease.Binding.EpochID ||
				effect.Target.Validate() != nil || len(effect.Digest) != sha256.Size || child == nil {
				return fmt.Errorf("%w: invalid child-generation lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectReshareReceiverGeneration:
			target := memory.generations[effect.Target]
			if lease.lease.Kind != RunReshare || lease.lease.State != RunLeaseCompleted ||
				effect.Target.KeyID != lease.lease.Binding.KeyID ||
				effect.Target.KeyGeneration == lease.lease.Binding.KeyGeneration ||
				effect.Target.EpochID == lease.lease.Binding.EpochID ||
				effect.Target.Validate() != nil || len(effect.Digest) != sha256.Size || target == nil {
				return fmt.Errorf("%w: invalid reshare receiver generation lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectRetirement:
			source := memory.generations[lease.lease.Binding]
			if lease.lease.Kind != RunReshare || lease.lease.State != RunLeaseCompleted ||
				validateCutoverBindings(lease.lease.Binding, effect.Target) != nil ||
				source == nil || source.record.Status != GenerationRetired ||
				len(source.record.Blob) != 0 || len(source.record.Metadata) != 0 {
				return fmt.Errorf("%w: invalid retirement lease effect", ErrLifecycleCorrupt)
			}
		default:
			return fmt.Errorf("%w: unknown lease effect", ErrLifecycleCorrupt)
		}
	}
	for disabledKeyID, disabled := range memory.refreshDisabled {
		if disabled.KeyID != disabledKeyID || !disabled.SessionID.Valid() || validateLifecycleReason(disabled.Reason) != nil {
			return fmt.Errorf("%w: invalid refresh-disabled record", ErrLifecycleCorrupt)
		}
		token, ok := memory.leaseBySession[disabled.SessionID]
		if !ok || memory.leaseEffects[token] == nil || memory.leaseEffects[token].Kind != storedLeaseEffectRefreshFailed {
			return fmt.Errorf("%w: refresh-disabled record missing lease effect", ErrLifecycleCorrupt)
		}
	}
	artifactOwners := make(map[string]string, len(memory.presigns))
	for presignID, presign := range memory.presigns {
		if presign == nil || validateLifecycleIdentifier(presignID) != nil || presign.binding.Validate() != nil || len(presign.artifactDigest) != sha256.Size {
			return fmt.Errorf("%w: invalid presign record", ErrLifecycleCorrupt)
		}
		artifactKey := string(presign.artifactDigest)
		if owner, duplicate := artifactOwners[artifactKey]; duplicate && owner != presignID {
			return fmt.Errorf("%w: duplicate presign public artifact", ErrLifecycleCorrupt)
		}
		artifactOwners[artifactKey] = presignID
		switch presign.state {
		case storedPresignAvailable:
			if !memory.isCurrentLocked(presign.binding) || len(presign.blob) == 0 || presign.attemptID != "" || presign.reason != "" {
				return fmt.Errorf("%w: invalid available presign", ErrLifecycleCorrupt)
			}
			metadataDigest := sha256.Sum256(presign.metadata)
			if !bytes.Equal(presign.artifactDigest, metadataDigest[:]) {
				return fmt.Errorf("%w: presign public artifact digest mismatch", ErrLifecycleCorrupt)
			}
		case storedPresignClaimed:
			attempt := memory.attempts[presign.attemptID]
			if !memory.isCurrentLocked(presign.binding) || len(presign.blob) != 0 || len(presign.metadata) != 0 || presign.attemptID == "" || presign.reason != "" ||
				attempt == nil || attempt.record.Binding != presign.binding || attempt.record.PresignID != presignID || attempt.record.Aborted {
				return fmt.Errorf("%w: invalid claimed presign", ErrLifecycleCorrupt)
			}
		case storedPresignBurned:
			if len(presign.blob) != 0 || len(presign.metadata) != 0 || validateLifecycleReason(presign.reason) != nil {
				return fmt.Errorf("%w: invalid burned presign", ErrLifecycleCorrupt)
			}
			if presign.attemptID != "" {
				attempt := memory.attempts[presign.attemptID]
				if attempt == nil || attempt.record.Binding != presign.binding || attempt.record.PresignID != presignID || (!attempt.record.Aborted && !attempt.record.Terminal()) {
					return fmt.Errorf("%w: invalid attempted burned presign", ErrLifecycleCorrupt)
				}
			}
		default:
			return fmt.Errorf("%w: invalid presign state", ErrLifecycleCorrupt)
		}
	}
	for attemptID, attempt := range memory.attempts {
		if attempt == nil || attempt.record.Intent.AttemptID != attemptID {
			return fmt.Errorf("%w: invalid attempt index", ErrLifecycleCorrupt)
		}
		record := attempt.record
		if record.Binding.Validate() != nil || record.Intent.Validate() != nil || validateLifecycleIdentifier(record.PresignID) != nil || len(record.OutboxDigest) != sha256.Size {
			return fmt.Errorf("%w: invalid attempt record", ErrLifecycleCorrupt)
		}
		leaseToken, ok := memory.leaseBySession[record.Intent.SessionID]
		lease := memory.leasesByToken[leaseToken]
		if !ok || lease == nil || lease.lease.Binding != record.Binding || lease.lease.Kind != RunSign {
			return fmt.Errorf("%w: attempt sign lease mismatch", ErrLifecycleCorrupt)
		}
		if !record.Terminal() && !memory.isCurrentLocked(record.Binding) {
			return fmt.Errorf("%w: nonterminal attempt is not current", ErrLifecycleCorrupt)
		}
		presign := memory.presigns[record.PresignID]
		if presign == nil || presign.binding != record.Binding || presign.attemptID != attemptID {
			return fmt.Errorf("%w: attempt presign index mismatch", ErrLifecycleCorrupt)
		}
		if record.Aborted {
			if presign.state != storedPresignBurned || validateLifecycleReason(record.AbortReason) != nil {
				return fmt.Errorf("%w: invalid aborted attempt", ErrLifecycleCorrupt)
			}
		} else if record.AbortReason != "" ||
			(presign.state != storedPresignClaimed && (!record.Terminal() || presign.state != storedPresignBurned)) {
			return fmt.Errorf("%w: invalid claimed attempt", ErrLifecycleCorrupt)
		}
		if record.Delivered != (len(record.Delivery) != 0) || record.Completed != (len(record.Completion) != 0) {
			return fmt.Errorf("%w: attempt progress mismatch", ErrLifecycleCorrupt)
		}
		if !record.Terminal() && !record.Aborted && len(record.ExactOutbox) == 0 {
			return fmt.Errorf("%w: pending attempt missing exact outbox", ErrLifecycleCorrupt)
		}
		if (record.Terminal() || record.Aborted) && len(record.ExactOutbox) != 0 {
			return fmt.Errorf("%w: terminal outbox retained", ErrLifecycleCorrupt)
		}
		if len(record.ExactOutbox) != 0 {
			digest := sha256.Sum256(record.ExactOutbox)
			if !bytes.Equal(record.OutboxDigest, digest[:]) {
				return fmt.Errorf("%w: exact outbox digest mismatch", ErrLifecycleCorrupt)
			}
		}
		if len(record.PresignMetadata) == 0 {
			return fmt.Errorf("%w: attempt missing public presign metadata", ErrLifecycleCorrupt)
		}
	}
	activeCutovers := 0
	for token, cutover := range memory.cutoversByToken {
		if cutover == nil || cutover.fence.Token != token || token > memory.nextCutoverToken || validateCutoverFence(cutover.fence) != nil {
			return fmt.Errorf("%w: invalid cutover record", ErrLifecycleCorrupt)
		}
		cutoverKeyID := cutover.fence.Source.KeyID
		switch cutover.state {
		case storedCutoverActive:
			activeCutovers++
			_, targetExists := memory.generations[cutover.fence.Target]
			if memory.cutoverByKey[cutoverKeyID] != token || !memory.isCurrentLocked(cutover.fence.Source) || targetExists ||
				memory.hasActiveLeaseForKeyLocked(cutoverKeyID) || memory.hasNonTerminalAttemptLocked(cutover.fence.Source) ||
				len(cutover.targetBlobDigest) != 0 || len(cutover.targetMetadataDigest) != 0 || cutover.reason != "" {
				return fmt.Errorf("%w: invalid active cutover", ErrLifecycleCorrupt)
			}
		case storedCutoverCommitted:
			if len(cutover.targetBlobDigest) != sha256.Size || len(cutover.targetMetadataDigest) != sha256.Size || cutover.reason != "" {
				return fmt.Errorf("%w: invalid committed cutover", ErrLifecycleCorrupt)
			}
			source := memory.generations[cutover.fence.Source]
			target := memory.generations[cutover.fence.Target]
			if source == nil || source.record.Status != GenerationRetired || target == nil {
				return fmt.Errorf("%w: committed cutover generation mismatch", ErrLifecycleCorrupt)
			}
			if target.record.Status == GenerationCurrent {
				blobDigest := sha256.Sum256(target.record.Blob)
				metadataDigest := sha256.Sum256(target.record.Metadata)
				if !bytes.Equal(cutover.targetBlobDigest, blobDigest[:]) || !bytes.Equal(cutover.targetMetadataDigest, metadataDigest[:]) {
					return fmt.Errorf("%w: committed cutover target digest mismatch", ErrLifecycleCorrupt)
				}
			}
		case storedCutoverAborted:
			if len(cutover.targetBlobDigest) != 0 || len(cutover.targetMetadataDigest) != 0 || validateLifecycleReason(cutover.reason) != nil {
				return fmt.Errorf("%w: invalid aborted cutover", ErrLifecycleCorrupt)
			}
		default:
			return fmt.Errorf("%w: invalid cutover state", ErrLifecycleCorrupt)
		}
	}
	if activeCutovers != len(memory.cutoverByKey) {
		return fmt.Errorf("%w: active cutover index mismatch", ErrLifecycleCorrupt)
	}
	return nil
}

func clearMemoryLifecycleState(memory *MemoryLifecycleStore) {
	if memory == nil {
		return
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	for _, generation := range memory.generations {
		if generation != nil {
			clearBytes(generation.record.Blob)
			clearBytes(generation.record.Metadata)
			generation.record.Blob = nil
			generation.record.Metadata = nil
		}
	}
	for _, presign := range memory.presigns {
		if presign != nil {
			clearBytes(presign.blob)
			clearBytes(presign.metadata)
			clearBytes(presign.artifactDigest)
			presign.blob = nil
			presign.metadata = nil
			presign.artifactDigest = nil
		}
	}
	for _, attempt := range memory.attempts {
		if attempt != nil {
			clearSignAttemptRecord(&attempt.record)
		}
	}
	for _, effect := range memory.leaseEffects {
		if effect != nil {
			clearBytes(effect.Digest)
			effect.Digest = nil
		}
	}
	for token, anchor := range memory.reshareReceivers {
		clearBytes(anchor.PlanDigest)
		clearBytes(anchor.SourceEpochDigest)
		anchor.PlanDigest = nil
		anchor.SourceEpochDigest = nil
		memory.reshareReceivers[token] = anchor
	}
	for _, cutover := range memory.cutoversByToken {
		if cutover != nil {
			clearBytes(cutover.targetBlobDigest)
			clearBytes(cutover.targetMetadataDigest)
			cutover.targetBlobDigest = nil
			cutover.targetMetadataDigest = nil
		}
	}
}

func clearSignAttemptRecord(record *SignAttemptRecord) {
	if record == nil {
		return
	}
	clearBytes(record.Intent.IntentDigest)
	clearBytes(record.PresignMetadata)
	clearBytes(record.ExactOutbox)
	clearBytes(record.OutboxDigest)
	clearBytes(record.Delivery)
	clearBytes(record.Completion)
	record.Intent.IntentDigest = nil
	record.PresignMetadata = nil
	record.ExactOutbox = nil
	record.OutboxDigest = nil
	record.Delivery = nil
	record.Completion = nil
}

func fileLifecycleBlobCacheKey(kind fileLifecycleBlobKind, plaintext []byte) [sha256.Size]byte {
	t := transcript.New("tssrun/file-lifecycle/blob-cache/v1")
	t.AppendString("kind", string(kind))
	t.AppendBytes("plaintext", plaintext)
	return t.Sum32()
}

func fileLifecycleManifestAAD(keyID string) string {
	return "tssrun-manifest:" + fileLifecycleKeyHash(keyID)
}

func fileLifecycleBlobAAD(keyID string, ref fileLifecycleBlobRef) string {
	return "tssrun-blob:" + fileLifecycleKeyHash(keyID) + ":" + string(ref.Kind) + ":" + ref.ID
}

func validFileLifecycleBlobKind(kind fileLifecycleBlobKind) bool {
	switch kind {
	case fileLifecycleBlobGeneration, fileLifecycleBlobMetadata, fileLifecycleBlobPresign, fileLifecycleBlobOutbox, fileLifecycleBlobDelivery, fileLifecycleBlobCompletion:
		return true
	default:
		return false
	}
}

func exceedsFileLifecycleRecordLimits(manifest fileLifecycleManifest) bool {
	return len(manifest.Currents) > fileLifecycleMaxRecords ||
		len(manifest.Generations) > fileLifecycleMaxRecords ||
		len(manifest.Leases) > fileLifecycleMaxRecords ||
		len(manifest.LeaseEffects) > fileLifecycleMaxRecords ||
		len(manifest.RefreshDisabled) > fileLifecycleMaxRecords ||
		len(manifest.ReshareReceivers) > fileLifecycleMaxRecords ||
		len(manifest.Presigns) > fileLifecycleMaxRecords ||
		len(manifest.Attempts) > fileLifecycleMaxRecords ||
		len(manifest.Cutovers) > fileLifecycleMaxRecords
}

func writeLifecycleFile(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func syncLifecycleDirectory(path string) error {
	// #nosec G304 G703 -- callers provide only constructor-validated store-owned
	// directories.
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
