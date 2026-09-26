package tssrun

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	fileLifecycleRootFormat      = "tssrun-lifecycle-root"
	fileLifecycleSnapshotFormat  = "tssrun-lifecycle-lineage"
	fileLifecycleSnapshotIDBytes = 16
	fileLifecycleMaxRootSize     = 16 << 20
	fileLifecycleMaxSnapshotSize = 32 << 20
	fileLifecycleMaxIndexSize    = 32 << 20
)

type fileLifecycleSnapshotRef struct {
	ID     string
	TxID   uint64
	Digest []byte
}

type fileLifecycleRootLineage struct {
	KeyID    string
	Snapshot fileLifecycleSnapshotRef
}

type fileLifecycleRootIndex struct {
	Namespace      string
	IdentifierHash string
	KeyID          string
	Tombstone      bool
}

type fileLifecycleRootBucket struct {
	Prefix   string
	Snapshot fileLifecycleSnapshotRef
}

type fileLifecycleIndexBucket struct {
	Format  string
	Prefix  string
	Entries []fileLifecycleRootIndex
}

type fileLifecycleRoot struct {
	Format   string
	StoreID  []byte
	TxID     uint64
	Lineages []fileLifecycleRootLineage
	Buckets  []fileLifecycleRootBucket
}

type fileLifecycleSnapshotPresign struct {
	PresignID      string
	Binding        GenerationBinding
	Blob           []byte
	Metadata       []byte
	ArtifactDigest []byte
	State          storedPresignState
	AttemptID      string
	Reason         string
}

type fileLifecycleSnapshotAttempt struct {
	Record SignAttemptRecord
}

type fileLifecycleSnapshotCutover struct {
	Fence                CutoverFence
	State                storedCutoverState
	TargetBlobDigest     []byte
	TargetMetadataDigest []byte
	Reason               string
}

type fileLifecycleSnapshotReshareReceiver struct {
	LeaseToken uint64
	Anchor     ReshareReceiverAnchor
}

type fileLifecycleLineageSnapshot struct {
	Format           string
	KeyID            string
	Currents         []GenerationBinding
	Generations      []GenerationRecord
	Leases           []RunLease
	LeaseEffects     []fileLifecycleLeaseEffect
	RefreshDisabled  []RefreshDisabledRecord
	ReshareReceivers []fileLifecycleSnapshotReshareReceiver
	Presigns         []fileLifecycleSnapshotPresign
	Attempts         []fileLifecycleSnapshotAttempt
	Cutovers         []fileLifecycleSnapshotCutover
	Tombstones       []storedLifecycleTombstone
}

func loadSnapshotLifecycleState(store *FileLifecycleStore, keyIDs []string) (*MemoryLifecycleStore, fileLifecycleRoot, map[string][]fileLifecycleRootIndex, error) {
	root, err := loadFileLifecycleRoot(store)
	if err != nil {
		return nil, fileLifecycleRoot{}, nil, err
	}
	memory := NewMemoryLifecycleStore()
	// The root transaction ID is also the allocation floor for both token
	// namespaces. A mutation can allocate at most one new lease or cutover, so
	// its token is the transaction ID published by that same root commit.
	memory.nextLeaseToken = root.TxID
	memory.nextCutoverToken = root.TxID
	oldIndexes := make(map[string][]fileLifecycleRootIndex, len(keyIDs))
	queue := uniqueLifecycleKeyIDs(keyIDs)
	loaded := make(map[string]struct{}, len(queue))
	for len(queue) != 0 {
		keyID := queue[0]
		queue = queue[1:]
		if _, ok := loaded[keyID]; ok {
			continue
		}
		loaded[keyID] = struct{}{}
		ref, ok := rootLineageRef(root, keyID)
		if !ok {
			continue
		}
		lineage, err := loadFileLifecycleLineage(store, keyID, ref)
		if err != nil {
			clearMemoryLifecycleState(memory)
			return nil, fileLifecycleRoot{}, nil, err
		}
		for _, effect := range lineage.leaseEffects {
			if effect.Target.KeyID != "" && effect.Target.KeyID != keyID {
				queue = append(queue, effect.Target.KeyID)
			}
		}
		if err := mergeMemoryLifecycleState(memory, lineage); err != nil {
			clearMemoryLifecycleState(lineage)
			clearMemoryLifecycleState(memory)
			return nil, fileLifecycleRoot{}, nil, err
		}
		clearMemoryLifecycleState(lineage)
	}
	if err := validateMemoryLifecycleStateForKey(memory, fileLifecycleGlobalKeyID); err != nil && !emptyMemoryLifecycleState(memory) {
		clearMemoryLifecycleState(memory)
		return nil, fileLifecycleRoot{}, nil, err
	}
	for _, keyID := range uniqueLifecycleKeyIDs(keyIDs) {
		oldIndexes[keyID] = lifecycleIndexesForKey(memory, keyID)
	}
	return memory, root, oldIndexes, nil
}

func persistSnapshotLifecycleState(store *FileLifecycleStore, keyIDs []string, memory *MemoryLifecycleStore, root fileLifecycleRoot, oldIndexes map[string][]fileLifecycleRootIndex) error {
	keys := uniqueLifecycleKeyIDs(keyIDs)
	nextRoot := root
	nextRoot.Format = fileLifecycleRootFormat
	nextRoot.StoreID = bytes.Clone(store.storeID)
	if root.TxID == math.MaxUint64 || memory.nextLeaseToken > root.TxID+1 || memory.nextCutoverToken > root.TxID+1 {
		return fmt.Errorf("%w: lifecycle transaction id exhausted or token allocation escaped transaction", ErrLifecycleCorrupt)
	}
	nextRoot.TxID = root.TxID + 1

	newPaths := make([]string, 0, len(keys))
	for _, keyID := range keys {
		snapshot := snapshotMemoryLifecycleState(memory, keyID)
		ref, path, err := writeFileLifecycleLineage(store, keyID, nextRoot.TxID, snapshot)
		if err != nil {
			removeSnapshotPaths(newPaths)
			return err
		}
		newPaths = append(newPaths, path)
		setRootLineageRef(&nextRoot, keyID, ref)
	}
	var oldEntries, newEntries []fileLifecycleRootIndex
	for _, keyID := range keys {
		oldEntries = append(oldEntries, oldIndexes[keyID]...)
		newEntries = append(newEntries, lifecycleIndexesForKey(memory, keyID)...)
	}
	bucketPaths, err := updateFileLifecycleIndexBuckets(store, &nextRoot, keys, oldEntries, newEntries)
	if err != nil {
		removeSnapshotPaths(newPaths)
		return err
	}
	newPaths = append(newPaths, bucketPaths...)
	renamed, err := replaceFileLifecycleRoot(store, nextRoot)
	if err != nil && !renamed {
		removeSnapshotPaths(newPaths)
	}
	return err
}

func loadFileLifecycleRoot(store *FileLifecycleStore) (fileLifecycleRoot, error) {
	path := filepath.Join(store.directory, fileLifecycleRootName)
	// #nosec G703 -- path appends one fixed filename to the constructor-validated private store root.
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileLifecycleRoot{Format: fileLifecycleRootFormat, StoreID: bytes.Clone(store.storeID)}, nil
	}
	if err != nil {
		return fileLifecycleRoot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > fileLifecycleMaxRootSize {
		return fileLifecycleRoot{}, fmt.Errorf("%w: invalid lifecycle root file", ErrLifecycleCorrupt)
	}
	// #nosec G304 G703 -- path is the fixed root file validated by Lstat above.
	encoded, err := os.ReadFile(path)
	if err != nil {
		return fileLifecycleRoot{}, err
	}
	defer clear(encoded)
	plaintext, err := openFileLifecycleData(store, "root", encoded)
	if err != nil {
		return fileLifecycleRoot{}, fmt.Errorf("%w: decrypt lifecycle root: %w", ErrLifecycleCorrupt, err)
	}
	defer clear(plaintext)
	var root fileLifecycleRoot
	if err := decodeFileLifecycleJSON(plaintext, &root); err != nil {
		return fileLifecycleRoot{}, fmt.Errorf("%w: decode lifecycle root: %w", ErrLifecycleCorrupt, err)
	}
	if root.Format != fileLifecycleRootFormat || !bytes.Equal(root.StoreID, store.storeID) {
		return fileLifecycleRoot{}, fmt.Errorf("%w: lifecycle root identity mismatch", ErrLifecycleCorrupt)
	}
	if err := validateFileLifecycleRoot(root); err != nil {
		return fileLifecycleRoot{}, err
	}
	return root, nil
}

func validateFileLifecycleRoot(root fileLifecycleRoot) error {
	seenKeys := make(map[string]struct{}, len(root.Lineages))
	for _, lineage := range root.Lineages {
		if validateLifecycleIdentifier(lineage.KeyID) != nil || lineage.Snapshot.ID == "" || lineage.Snapshot.TxID == 0 || len(lineage.Snapshot.Digest) != sha256.Size {
			return fmt.Errorf("%w: invalid lifecycle root lineage", ErrLifecycleCorrupt)
		}
		if _, ok := seenKeys[lineage.KeyID]; ok {
			return fmt.Errorf("%w: duplicate lifecycle root lineage", ErrLifecycleCorrupt)
		}
		seenKeys[lineage.KeyID] = struct{}{}
	}
	seenBuckets := make(map[string]struct{}, len(root.Buckets))
	for _, bucket := range root.Buckets {
		if len(bucket.Prefix) != 4 || bucket.Snapshot.ID == "" || bucket.Snapshot.TxID == 0 || len(bucket.Snapshot.Digest) != sha256.Size {
			return fmt.Errorf("%w: invalid lifecycle root index bucket", ErrLifecycleCorrupt)
		}
		if _, err := hex.DecodeString(bucket.Prefix); err != nil {
			return fmt.Errorf("%w: invalid lifecycle root index prefix", ErrLifecycleCorrupt)
		}
		if _, ok := seenBuckets[bucket.Prefix]; ok {
			return fmt.Errorf("%w: duplicate lifecycle root index bucket", ErrLifecycleCorrupt)
		}
		seenBuckets[bucket.Prefix] = struct{}{}
	}
	return nil
}

func replaceFileLifecycleRoot(store *FileLifecycleStore, root fileLifecycleRoot) (bool, error) {
	plaintext, err := json.Marshal(root)
	if err != nil {
		return false, err
	}
	defer clear(plaintext)
	if len(plaintext) > fileLifecycleMaxRootSize/2 {
		return false, fmt.Errorf("%w: lifecycle root too large", ErrInvalidLifecycleRecord)
	}
	encoded, err := sealFileLifecycleData(store, "root", plaintext)
	if err != nil {
		return false, err
	}
	defer clear(encoded)
	temporary, err := os.CreateTemp(store.directory, ".root-*.tmp")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			// #nosec G703 -- temporaryPath was returned by CreateTemp for the validated store root.
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	if err := writeLifecycleFile(temporary, encoded); err != nil {
		return false, err
	}
	if err := store.injectFault(FileLifecycleFaultAfterRootWrite); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := store.injectFault(FileLifecycleFaultAfterRootSync); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	path := filepath.Join(store.directory, fileLifecycleRootName)
	// #nosec G703 -- both paths are constrained to the constructor-validated store root.
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, err
	}
	remove = false
	if err := store.injectFault(FileLifecycleFaultAfterRootRename); err != nil {
		return true, err
	}
	if err := syncLifecycleDirectory(store.directory); err != nil {
		return true, err
	}
	if err := store.injectFault(FileLifecycleFaultAfterRootDirectorySync); err != nil {
		return true, err
	}
	return true, nil
}

func writeFileLifecycleLineage(store *FileLifecycleStore, keyID string, txID uint64, memory *MemoryLifecycleStore) (fileLifecycleSnapshotRef, string, error) {
	snapshot := encodeLineageSnapshot(memory, keyID)
	plaintext, err := json.Marshal(snapshot)
	if err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	defer clear(plaintext)
	if len(plaintext) > fileLifecycleMaxSnapshotSize/2 {
		return fileLifecycleSnapshotRef{}, "", fmt.Errorf("%w: lifecycle lineage snapshot too large", ErrInvalidLifecycleRecord)
	}
	idBytes := make([]byte, fileLifecycleSnapshotIDBytes)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	id := hex.EncodeToString(idBytes)
	aad := fileLifecycleSnapshotAAD(keyID, id, txID)
	encoded, err := sealFileLifecycleData(store, aad, plaintext)
	if err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	dir := filepath.Join(store.directory, fileLifecycleSnapshotsDirectory, fileLifecycleKeyHash(keyID))
	if err := preparePrivateLifecycleDirectory(dir); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	path := filepath.Join(dir, id+".enc")
	// #nosec G304 G703 -- dir is hash-addressed under the private snapshot root and id is random fixed-width hex.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			// #nosec G703 -- path is the internally generated immutable snapshot path described above.
			_ = os.Remove(path)
		}
	}()
	if err := writeLifecycleFile(file, encoded); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := store.injectFault(FileLifecycleFaultAfterBlobWrite); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := file.Sync(); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := store.injectFault(FileLifecycleFaultAfterBlobSync); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := file.Close(); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := syncLifecycleDirectory(dir); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	remove = false
	return fileLifecycleSnapshotRef{ID: id, TxID: txID, Digest: bytes.Clone(digest[:])}, path, nil
}

func loadFileLifecycleLineage(store *FileLifecycleStore, keyID string, ref fileLifecycleSnapshotRef) (*MemoryLifecycleStore, error) {
	if len(ref.ID) != fileLifecycleSnapshotIDBytes*2 || ref.TxID == 0 || len(ref.Digest) != sha256.Size {
		return nil, ErrLifecycleCorrupt
	}
	path := filepath.Join(store.directory, fileLifecycleSnapshotsDirectory, fileLifecycleKeyHash(keyID), ref.ID+".enc")
	// #nosec G703 -- keyID is represented only by SHA-256 hex and ref.ID is validated fixed-width hex.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > fileLifecycleMaxSnapshotSize {
		return nil, ErrLifecycleCorrupt
	}
	// #nosec G304 G703 -- path is the validated hash-addressed immutable lineage path above.
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if !bytes.Equal(digest[:], ref.Digest) {
		return nil, fmt.Errorf("%w: lifecycle snapshot digest mismatch", ErrLifecycleCorrupt)
	}
	plaintext, err := openFileLifecycleData(store, fileLifecycleSnapshotAAD(keyID, ref.ID, ref.TxID), encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt lifecycle lineage: %w", ErrLifecycleCorrupt, err)
	}
	defer clear(plaintext)
	var snapshot fileLifecycleLineageSnapshot
	if err := decodeFileLifecycleJSON(plaintext, &snapshot); err != nil {
		return nil, fmt.Errorf("%w: decode lifecycle lineage: %w", ErrLifecycleCorrupt, err)
	}
	if snapshot.Format != fileLifecycleSnapshotFormat || snapshot.KeyID != keyID {
		return nil, fmt.Errorf("%w: lifecycle lineage identity mismatch", ErrLifecycleCorrupt)
	}
	return decodeLineageSnapshot(snapshot)
}

func encodeLineageSnapshot(memory *MemoryLifecycleStore, keyID string) fileLifecycleLineageSnapshot {
	snapshot := fileLifecycleLineageSnapshot{Format: fileLifecycleSnapshotFormat, KeyID: keyID}
	for _, current := range memory.current {
		if current.KeyID == keyID {
			snapshot.Currents = append(snapshot.Currents, current)
		}
	}
	for binding, generation := range memory.generations {
		if binding.KeyID == keyID {
			snapshot.Generations = append(snapshot.Generations, generation.record.Clone())
		}
	}
	leaseTokens := make(map[uint64]struct{})
	for token, lease := range memory.leasesByToken {
		if lease.lease.Binding.KeyID == keyID {
			snapshot.Leases = append(snapshot.Leases, lease.lease.Clone())
			leaseTokens[token] = struct{}{}
		}
	}
	for token, effect := range memory.leaseEffects {
		if _, ok := leaseTokens[token]; ok {
			snapshot.LeaseEffects = append(snapshot.LeaseEffects, fileLifecycleLeaseEffect{
				LeaseToken: effect.LeaseToken, Kind: effect.Kind, PresignID: effect.PresignID,
				Target: effect.Target, Digest: bytes.Clone(effect.Digest), Reason: effect.Reason, CutoverToken: effect.CutoverToken,
			})
		}
	}
	if disabled, ok := memory.refreshDisabled[keyID]; ok {
		snapshot.RefreshDisabled = append(snapshot.RefreshDisabled, disabled.Clone())
	}
	for token, anchor := range memory.reshareReceivers {
		if anchor.Source.KeyID == keyID {
			snapshot.ReshareReceivers = append(snapshot.ReshareReceivers, fileLifecycleSnapshotReshareReceiver{LeaseToken: token, Anchor: anchor.Clone()})
		}
	}
	for id, presign := range memory.presigns {
		if presign.binding.KeyID == keyID {
			snapshot.Presigns = append(snapshot.Presigns, fileLifecycleSnapshotPresign{
				PresignID: id, Binding: presign.binding, Blob: bytes.Clone(presign.blob), Metadata: bytes.Clone(presign.metadata),
				ArtifactDigest: bytes.Clone(presign.artifactDigest), State: presign.state, AttemptID: presign.attemptID, Reason: presign.reason,
			})
		}
	}
	for _, attempt := range memory.attempts {
		if attempt.record.Binding.KeyID == keyID {
			snapshot.Attempts = append(snapshot.Attempts, fileLifecycleSnapshotAttempt{Record: attempt.record.Clone()})
		}
	}
	for _, cutover := range memory.cutoversByToken {
		if cutover.fence.Source.KeyID == keyID {
			snapshot.Cutovers = append(snapshot.Cutovers, fileLifecycleSnapshotCutover{
				Fence: cutover.fence, State: cutover.state, TargetBlobDigest: bytes.Clone(cutover.targetBlobDigest),
				TargetMetadataDigest: bytes.Clone(cutover.targetMetadataDigest), Reason: cutover.reason,
			})
		}
	}
	for _, tombstone := range memory.tombstones {
		if tombstone.KeyID == keyID {
			clone := tombstone
			clone.Digest = bytes.Clone(tombstone.Digest)
			snapshot.Tombstones = append(snapshot.Tombstones, clone)
		}
	}
	sortLineageSnapshot(&snapshot)
	return snapshot
}

func decodeLineageSnapshot(snapshot fileLifecycleLineageSnapshot) (*MemoryLifecycleStore, error) {
	memory := NewMemoryLifecycleStore()
	for _, current := range snapshot.Currents {
		memory.current[current.KeyID] = current
	}
	for _, record := range snapshot.Generations {
		clone := record.Clone()
		memory.generations[clone.Binding] = &storedGeneration{record: clone}
	}
	for _, lease := range snapshot.Leases {
		memory.leasesByToken[lease.Token] = &storedRunLease{lease: lease}
		memory.leaseBySession[lease.SessionID] = lease.Token
	}
	for _, effect := range snapshot.LeaseEffects {
		memory.leaseEffects[effect.LeaseToken] = &storedLeaseEffect{
			LeaseToken: effect.LeaseToken, Kind: effect.Kind, PresignID: effect.PresignID, Target: effect.Target,
			Digest: bytes.Clone(effect.Digest), Reason: effect.Reason, CutoverToken: effect.CutoverToken,
		}
	}
	for _, disabled := range snapshot.RefreshDisabled {
		memory.refreshDisabled[disabled.KeyID] = disabled.Clone()
	}
	for _, receiver := range snapshot.ReshareReceivers {
		memory.reshareReceivers[receiver.LeaseToken] = receiver.Anchor.Clone()
	}
	for _, presign := range snapshot.Presigns {
		memory.presigns[presign.PresignID] = &storedPresign{
			binding: presign.Binding, blob: bytes.Clone(presign.Blob), metadata: bytes.Clone(presign.Metadata),
			artifactDigest: bytes.Clone(presign.ArtifactDigest), state: presign.State, attemptID: presign.AttemptID, reason: presign.Reason,
		}
	}
	for _, attempt := range snapshot.Attempts {
		memory.attempts[attempt.Record.Intent.AttemptID] = &storedAttempt{record: attempt.Record.Clone()}
	}
	for _, cutover := range snapshot.Cutovers {
		stored := &storedCutover{
			fence: cutover.Fence, state: cutover.State, targetBlobDigest: bytes.Clone(cutover.TargetBlobDigest),
			targetMetadataDigest: bytes.Clone(cutover.TargetMetadataDigest), reason: cutover.Reason,
		}
		memory.cutoversByToken[cutover.Fence.Token] = stored
		if cutover.State == storedCutoverActive {
			memory.cutoverByKey[cutover.Fence.Source.KeyID] = cutover.Fence.Token
		}
	}
	for _, tombstone := range snapshot.Tombstones {
		clone := tombstone
		clone.Digest = bytes.Clone(tombstone.Digest)
		memory.tombstones[lifecycleTombstoneMapKey(clone.Namespace, clone.IdentifierHash)] = clone
	}
	return memory, nil
}

func snapshotMemoryLifecycleState(memory *MemoryLifecycleStore, keyID string) *MemoryLifecycleStore {
	snapshot, _ := decodeLineageSnapshot(encodeLineageSnapshot(memory, keyID))
	return snapshot
}

func mergeMemoryLifecycleState(dst, src *MemoryLifecycleStore) error {
	for binding, generation := range src.generations {
		if _, ok := dst.generations[binding]; ok {
			return ErrLifecycleCorrupt
		}
		dst.generations[binding] = &storedGeneration{record: generation.record.Clone()}
	}
	for keyID, binding := range src.current {
		if _, ok := dst.current[keyID]; ok {
			return ErrLifecycleCorrupt
		}
		dst.current[keyID] = binding
	}
	for token, lease := range src.leasesByToken {
		if _, ok := dst.leasesByToken[token]; ok {
			return ErrLifecycleCorrupt
		}
		dst.leasesByToken[token] = &storedRunLease{lease: lease.lease.Clone()}
		dst.leaseBySession[lease.lease.SessionID] = token
	}
	for token, effect := range src.leaseEffects {
		dst.leaseEffects[token] = &storedLeaseEffect{
			LeaseToken: effect.LeaseToken, Kind: effect.Kind, PresignID: effect.PresignID, Target: effect.Target,
			Digest: bytes.Clone(effect.Digest), Reason: effect.Reason, CutoverToken: effect.CutoverToken,
		}
	}
	for keyID, record := range src.refreshDisabled {
		dst.refreshDisabled[keyID] = record.Clone()
	}
	for token, anchor := range src.reshareReceivers {
		dst.reshareReceivers[token] = anchor.Clone()
	}
	for id, presign := range src.presigns {
		if _, ok := dst.presigns[id]; ok {
			return ErrLifecycleCorrupt
		}
		dst.presigns[id] = &storedPresign{
			binding: presign.binding, blob: bytes.Clone(presign.blob), metadata: bytes.Clone(presign.metadata),
			artifactDigest: bytes.Clone(presign.artifactDigest), state: presign.state, attemptID: presign.attemptID, reason: presign.reason,
		}
	}
	for id, attempt := range src.attempts {
		if _, ok := dst.attempts[id]; ok {
			return ErrLifecycleCorrupt
		}
		dst.attempts[id] = &storedAttempt{record: attempt.record.Clone()}
	}
	for token, cutover := range src.cutoversByToken {
		dst.cutoversByToken[token] = &storedCutover{
			fence: cutover.fence, state: cutover.state, targetBlobDigest: bytes.Clone(cutover.targetBlobDigest),
			targetMetadataDigest: bytes.Clone(cutover.targetMetadataDigest), reason: cutover.reason,
		}
		if cutover.state == storedCutoverActive {
			dst.cutoverByKey[cutover.fence.Source.KeyID] = token
		}
	}
	for key, tombstone := range src.tombstones {
		if _, exists := dst.tombstones[key]; exists {
			return ErrLifecycleCorrupt
		}
		clone := tombstone
		clone.Digest = bytes.Clone(tombstone.Digest)
		dst.tombstones[key] = clone
	}
	return nil
}

func lifecycleIndexesForKey(memory *MemoryLifecycleStore, keyID string) []fileLifecycleRootIndex {
	var out []fileLifecycleRootIndex
	for _, lease := range memory.leasesByToken {
		if lease.lease.Binding.KeyID == keyID {
			out = append(out, newLifecycleRootIndex("session", lease.lease.SessionID[:], keyID))
		}
	}
	for id, presign := range memory.presigns {
		if presign.binding.KeyID != keyID {
			continue
		}
		out = append(out, newLifecycleRootIndex("presign", []byte(id), keyID))
		out = append(out, newLifecycleRootIndex("presign-artifact", presign.artifactDigest, keyID))
	}
	for id, attempt := range memory.attempts {
		if attempt.record.Binding.KeyID == keyID {
			out = append(out, newLifecycleRootIndex("attempt", []byte(id), keyID))
		}
	}
	for _, tombstone := range memory.tombstones {
		if tombstone.KeyID == keyID {
			out = append(out, fileLifecycleRootIndex{
				Namespace: tombstone.Namespace, IdentifierHash: tombstone.IdentifierHash,
				KeyID: keyID, Tombstone: true,
			})
		}
	}
	return out
}

func updateFileLifecycleIndexBuckets(
	store *FileLifecycleStore,
	root *fileLifecycleRoot,
	keys []string,
	oldEntries, newEntries []fileLifecycleRootIndex,
) ([]string, error) {
	prefixes := make(map[string]struct{})
	for _, entry := range append(slices.Clone(oldEntries), newEntries...) {
		prefixes[indexBucketPrefix(entry)] = struct{}{}
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, keyID := range keys {
		keySet[keyID] = struct{}{}
	}
	orderedPrefixes := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		orderedPrefixes = append(orderedPrefixes, prefix)
	}
	sort.Strings(orderedPrefixes)
	var newPaths []string
	for _, prefix := range orderedPrefixes {
		entries, err := loadFileLifecycleIndexBucket(store, *root, prefix)
		if err != nil {
			removeSnapshotPaths(newPaths)
			return nil, err
		}
		filtered := entries[:0]
		for _, entry := range entries {
			if _, replace := keySet[entry.KeyID]; !replace {
				filtered = append(filtered, entry)
			}
		}
		for _, entry := range newEntries {
			if indexBucketPrefix(entry) == prefix {
				filtered = append(filtered, entry)
			}
		}
		filtered, err = validateAndCanonicalizeIndexEntries(filtered)
		if err != nil {
			removeSnapshotPaths(newPaths)
			return nil, err
		}
		if len(filtered) == 0 {
			removeRootBucketRef(root, prefix)
			continue
		}
		ref, path, err := writeFileLifecycleIndexBucket(store, prefix, root.TxID, filtered)
		if err != nil {
			removeSnapshotPaths(newPaths)
			return nil, err
		}
		newPaths = append(newPaths, path)
		setRootBucketRef(root, prefix, ref)
	}
	return newPaths, nil
}

func validateAndCanonicalizeIndexEntries(entries []fileLifecycleRootIndex) ([]fileLifecycleRootIndex, error) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Namespace != entries[j].Namespace {
			return entries[i].Namespace < entries[j].Namespace
		}
		if entries[i].IdentifierHash != entries[j].IdentifierHash {
			return entries[i].IdentifierHash < entries[j].IdentifierHash
		}
		return entries[i].KeyID < entries[j].KeyID
	})
	out := entries[:0]
	for _, entry := range entries {
		if !validLifecycleTombstoneNamespace(entry.Namespace) || len(entry.IdentifierHash) != sha256.Size*2 || validateLifecycleIdentifier(entry.KeyID) != nil {
			return nil, ErrLifecycleCorrupt
		}
		if len(out) != 0 && out[len(out)-1].Namespace == entry.Namespace && out[len(out)-1].IdentifierHash == entry.IdentifierHash {
			if out[len(out)-1].KeyID == entry.KeyID && out[len(out)-1].Tombstone == entry.Tombstone {
				continue
			}
			switch entry.Namespace {
			case "session":
				return nil, ErrSessionAlreadyUsed
			case "presign", "presign-artifact":
				return nil, ErrPresignUnavailable
			case "attempt":
				return nil, ErrAttemptConflict
			default:
				return nil, ErrLifecycleCorrupt
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

func writeFileLifecycleIndexBucket(store *FileLifecycleStore, prefix string, txID uint64, entries []fileLifecycleRootIndex) (fileLifecycleSnapshotRef, string, error) {
	bucket := fileLifecycleIndexBucket{Format: "tssrun-lifecycle-index", Prefix: prefix, Entries: entries}
	plaintext, err := json.Marshal(bucket)
	if err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	defer clear(plaintext)
	if len(plaintext) > fileLifecycleMaxIndexSize/2 {
		return fileLifecycleSnapshotRef{}, "", fmt.Errorf("%w: lifecycle index bucket too large", ErrInvalidLifecycleRecord)
	}
	idBytes := make([]byte, fileLifecycleSnapshotIDBytes)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	id := hex.EncodeToString(idBytes)
	encoded, err := sealFileLifecycleData(store, fileLifecycleIndexAAD(prefix, id, txID), plaintext)
	if err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	dir := filepath.Join(store.directory, fileLifecycleIndexesDirectory, prefix)
	if err := preparePrivateLifecycleDirectory(dir); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	path := filepath.Join(dir, id+".enc")
	// #nosec G304 G703 -- prefix and id are validated fixed-width hex below the private index root.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			// #nosec G703 -- path is the internally generated immutable index path described above.
			_ = os.Remove(path)
		}
	}()
	if err := writeLifecycleFile(file, encoded); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := store.injectFault(FileLifecycleFaultAfterBlobWrite); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := file.Sync(); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := store.injectFault(FileLifecycleFaultAfterBlobSync); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := file.Close(); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	if err := syncLifecycleDirectory(dir); err != nil {
		return fileLifecycleSnapshotRef{}, "", err
	}
	remove = false
	return fileLifecycleSnapshotRef{ID: id, TxID: txID, Digest: bytes.Clone(digest[:])}, path, nil
}

func loadFileLifecycleIndexBucket(store *FileLifecycleStore, root fileLifecycleRoot, prefix string) ([]fileLifecycleRootIndex, error) {
	ref, ok := rootBucketRef(root, prefix)
	if !ok {
		return nil, nil
	}
	path := filepath.Join(store.directory, fileLifecycleIndexesDirectory, prefix, ref.ID+".enc")
	if len(prefix) != 4 || len(ref.ID) != fileLifecycleSnapshotIDBytes*2 || ref.TxID == 0 || len(ref.Digest) != sha256.Size {
		return nil, ErrLifecycleCorrupt
	}
	// #nosec G703 -- prefix and ref.ID are validated fixed-width hex under the private index root.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > fileLifecycleMaxIndexSize {
		return nil, ErrLifecycleCorrupt
	}
	// #nosec G304 G703 -- path is the validated immutable index path above.
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if !bytes.Equal(digest[:], ref.Digest) {
		return nil, ErrLifecycleCorrupt
	}
	plaintext, err := openFileLifecycleData(store, fileLifecycleIndexAAD(prefix, ref.ID, ref.TxID), encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt lifecycle index bucket: %w", ErrLifecycleCorrupt, err)
	}
	defer clear(plaintext)
	var bucket fileLifecycleIndexBucket
	if err := decodeFileLifecycleJSON(plaintext, &bucket); err != nil {
		return nil, fmt.Errorf("%w: decode lifecycle index bucket: %w", ErrLifecycleCorrupt, err)
	}
	if bucket.Format != "tssrun-lifecycle-index" || bucket.Prefix != prefix {
		return nil, ErrLifecycleCorrupt
	}
	return validateAndCanonicalizeIndexEntries(bucket.Entries)
}

func rootBucketRef(root fileLifecycleRoot, prefix string) (fileLifecycleSnapshotRef, bool) {
	for _, bucket := range root.Buckets {
		if bucket.Prefix == prefix {
			return bucket.Snapshot, true
		}
	}
	return fileLifecycleSnapshotRef{}, false
}

func setRootBucketRef(root *fileLifecycleRoot, prefix string, ref fileLifecycleSnapshotRef) {
	for i := range root.Buckets {
		if root.Buckets[i].Prefix == prefix {
			root.Buckets[i].Snapshot = ref
			return
		}
	}
	root.Buckets = append(root.Buckets, fileLifecycleRootBucket{Prefix: prefix, Snapshot: ref})
	sort.Slice(root.Buckets, func(i, j int) bool { return root.Buckets[i].Prefix < root.Buckets[j].Prefix })
}

func removeRootBucketRef(root *fileLifecycleRoot, prefix string) {
	root.Buckets = slices.DeleteFunc(root.Buckets, func(bucket fileLifecycleRootBucket) bool {
		return bucket.Prefix == prefix
	})
}

func indexBucketPrefix(entry fileLifecycleRootIndex) string {
	return entry.IdentifierHash[:4]
}

func fileLifecycleIndexAAD(prefix, id string, txID uint64) string {
	return fmt.Sprintf("index:%s:%s:%d", prefix, id, txID)
}

func newLifecycleRootIndex(namespace string, identifier []byte, keyID string) fileLifecycleRootIndex {
	digest := sha256.Sum256(append(append([]byte(namespace), 0), identifier...))
	return fileLifecycleRootIndex{Namespace: namespace, IdentifierHash: hex.EncodeToString(digest[:]), KeyID: keyID}
}

func rootLineageRef(root fileLifecycleRoot, keyID string) (fileLifecycleSnapshotRef, bool) {
	for _, lineage := range root.Lineages {
		if lineage.KeyID == keyID {
			return lineage.Snapshot, true
		}
	}
	return fileLifecycleSnapshotRef{}, false
}

func setRootLineageRef(root *fileLifecycleRoot, keyID string, ref fileLifecycleSnapshotRef) {
	for i := range root.Lineages {
		if root.Lineages[i].KeyID == keyID {
			root.Lineages[i].Snapshot = ref
			return
		}
	}
	root.Lineages = append(root.Lineages, fileLifecycleRootLineage{KeyID: keyID, Snapshot: ref})
	sort.Slice(root.Lineages, func(i, j int) bool { return root.Lineages[i].KeyID < root.Lineages[j].KeyID })
}

func sortLineageSnapshot(snapshot *fileLifecycleLineageSnapshot) {
	sort.Slice(snapshot.Currents, func(i, j int) bool { return snapshot.Currents[i].KeyID < snapshot.Currents[j].KeyID })
	sort.Slice(snapshot.Generations, func(i, j int) bool {
		a, b := snapshot.Generations[i].Binding, snapshot.Generations[j].Binding
		if a.KeyGeneration != b.KeyGeneration {
			return a.KeyGeneration < b.KeyGeneration
		}
		return bytes.Compare(a.EpochID[:], b.EpochID[:]) < 0
	})
	sort.Slice(snapshot.Leases, func(i, j int) bool { return snapshot.Leases[i].Token < snapshot.Leases[j].Token })
	sort.Slice(snapshot.LeaseEffects, func(i, j int) bool { return snapshot.LeaseEffects[i].LeaseToken < snapshot.LeaseEffects[j].LeaseToken })
	sort.Slice(snapshot.Presigns, func(i, j int) bool { return snapshot.Presigns[i].PresignID < snapshot.Presigns[j].PresignID })
	sort.Slice(snapshot.Attempts, func(i, j int) bool {
		return snapshot.Attempts[i].Record.Intent.AttemptID < snapshot.Attempts[j].Record.Intent.AttemptID
	})
	sort.Slice(snapshot.Cutovers, func(i, j int) bool { return snapshot.Cutovers[i].Fence.Token < snapshot.Cutovers[j].Fence.Token })
	sort.Slice(snapshot.Tombstones, func(i, j int) bool {
		if snapshot.Tombstones[i].Namespace != snapshot.Tombstones[j].Namespace {
			return snapshot.Tombstones[i].Namespace < snapshot.Tombstones[j].Namespace
		}
		return snapshot.Tombstones[i].IdentifierHash < snapshot.Tombstones[j].IdentifierHash
	})
}

func fileLifecycleSnapshotAAD(keyID, id string, txID uint64) string {
	return fmt.Sprintf("snapshot:%s:%s:%d", fileLifecycleKeyHash(keyID), id, txID)
}

func uniqueLifecycleKeyIDs(keyIDs []string) []string {
	out := slices.Clone(keyIDs)
	sort.Strings(out)
	return slices.Compact(out)
}

func emptyMemoryLifecycleState(memory *MemoryLifecycleStore) bool {
	return memory == nil || (len(memory.generations) == 0 && len(memory.leasesByToken) == 0 && len(memory.presigns) == 0 && len(memory.attempts) == 0 && len(memory.cutoversByToken) == 0 && len(memory.tombstones) == 0)
}

func removeSnapshotPaths(paths []string) {
	for _, path := range paths {
		// #nosec G703 -- callers supply only paths created in the current unpublished snapshot transaction.
		_ = os.Remove(path)
	}
}

func recoverFileLifecycleSnapshotArtifacts(store *FileLifecycleStore) error {
	release, err := store.acquireLifecycleLocks(context.Background(), []string{fileLifecycleGlobalKeyID})
	if err != nil {
		return err
	}
	defer release()
	root, err := loadFileLifecycleRoot(store)
	if err != nil {
		return err
	}
	referenced := make(map[string]struct{}, len(root.Lineages)+len(root.Buckets))
	for _, lineage := range root.Lineages {
		path := filepath.Join(store.directory, fileLifecycleSnapshotsDirectory, fileLifecycleKeyHash(lineage.KeyID), lineage.Snapshot.ID+".enc")
		referenced[path] = struct{}{}
	}
	for _, bucket := range root.Buckets {
		path := filepath.Join(store.directory, fileLifecycleIndexesDirectory, bucket.Prefix, bucket.Snapshot.ID+".enc")
		referenced[path] = struct{}{}
	}
	changedDirectories := make(map[string]struct{})
	for _, artifactRoot := range []string{
		filepath.Join(store.directory, fileLifecycleSnapshotsDirectory),
		filepath.Join(store.directory, fileLifecycleIndexesDirectory),
	} {
		if err := removeUnreferencedLifecycleArtifacts(artifactRoot, referenced, changedDirectories); err != nil {
			return err
		}
	}
	rootedStore, err := os.OpenRoot(store.directory)
	if err != nil {
		return err
	}
	defer func() { _ = rootedStore.Close() }()
	entries, err := fs.ReadDir(rootedStore.FS(), ".")
	if err != nil {
		return err
	}
	rootChanged := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".root-") || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		if err := rootedStore.Remove(entry.Name()); err != nil {
			return err
		}
		rootChanged = true
	}
	for directory := range changedDirectories {
		if err := syncLifecycleDirectory(directory); err != nil {
			return err
		}
	}
	if rootChanged {
		return syncLifecycleDirectory(store.directory)
	}
	return nil
}

func removeUnreferencedLifecycleArtifacts(artifactRoot string, referenced, changedDirectories map[string]struct{}) error {
	rootedArtifacts, err := os.OpenRoot(artifactRoot)
	if err != nil {
		return err
	}
	walkErr := fs.WalkDir(rootedArtifacts.FS(), ".", func(relativePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".enc") {
			return fmt.Errorf("%w: unexpected lifecycle snapshot artifact", ErrLifecycleCorrupt)
		}
		path := filepath.Join(artifactRoot, filepath.FromSlash(relativePath))
		if _, ok := referenced[path]; ok {
			return nil
		}
		if err := rootedArtifacts.Remove(filepath.FromSlash(relativePath)); err != nil {
			return err
		}
		changedDirectories[filepath.Dir(path)] = struct{}{}
		return nil
	})
	closeErr := rootedArtifacts.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}
