package tssrun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileLifecycleStoreConcurrentFirstOpenUsesOneKDFPerInstance(t *testing.T) {
	directory := t.TempDir()
	// #nosec G302 -- 0700 is the required private directory mode; this is not a regular file.
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("concurrent-first-open-passphrase")
	stores := make([]*FileLifecycleStore, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range stores {
		wg.Go(func() {
			<-start
			stores[i], errs[i] = NewFileLifecycleStore(directory, passphrase, fastFileLifecycleParams)
		})
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent open %d: %v", i, err)
		}
		if stores[i].kdfDerivations != 1 {
			t.Fatalf("concurrent open %d KDF count=%d", i, stores[i].kdfDerivations)
		}
		store := stores[i]
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Errorf("close concurrent store: %v", err)
			}
		})
	}
	if !bytes.Equal(stores[0].storeID, stores[1].storeID) {
		t.Fatal("concurrent first opens selected different store identities")
	}
}

func TestFileLifecycleStoreCompactionPreservesOneUseTombstones(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("compaction-passphrase")
	store := newTestFileLifecycleStore(t, directory, passphrase)
	binding := testGenerationBinding("compact-key", "gen-1", "compact-epoch")
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), nil); err != nil {
		t.Fatal(err)
	}
	commitTestAvailablePresign(t, store, binding, "compact-presign", []byte("presign-secret"), []byte("presign-metadata"), "compact")
	signSession := fileLifecycleSessionID(t, "compact-sign")
	signLease, err := store.AcquireRunLease(ctx, binding, RunSign, signSession)
	if err != nil {
		t.Fatal(err)
	}
	intent := SignAttemptIntent{AttemptID: "compact-attempt", SessionID: signSession, IntentDigest: testRunDigest("compact-intent")}
	commit, err := store.CommitSignAttempt(ctx, binding, "compact-presign", intent, []byte("exact-outbox"))
	if err != nil {
		t.Fatal(err)
	}
	query := commit.Record.Query()
	if _, err := store.MarkAttemptDelivered(ctx, query, []byte("delivery")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteAttempt(ctx, query, []byte("completion")); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRunLease(ctx, signLease, LeaseCompleted); err != nil {
		t.Fatal(err)
	}
	rootBefore, err := loadFileLifecycleRoot(store)
	if err != nil {
		t.Fatal(err)
	}
	oldRef, ok := rootLineageRef(rootBefore, binding.KeyID)
	if !ok {
		t.Fatal("missing pre-compaction lineage snapshot")
	}
	oldSnapshot := filepath.Join(directory, fileLifecycleSnapshotsDirectory, fileLifecycleKeyHash(binding.KeyID), oldRef.ID+".enc")

	report, err := store.CompactLifecycle(ctx, LifecycleCompactionRequest{
		KeyID: binding.KeyID, ExpectedCurrent: binding, RetainRecentTerminal: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Attempts != 1 || report.Presigns != 1 || report.Leases < 2 {
		t.Fatalf("unexpected compaction report: %+v", report)
	}
	if _, err := os.Lstat(oldSnapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded encrypted snapshot survived explicit compaction: %v", err)
	}
	if _, err := store.QueryAttemptOutcome(ctx, query); !errors.Is(err, ErrLifecycleHistoryCompacted) {
		t.Fatalf("compacted attempt query = %v, want ErrLifecycleHistoryCompacted", err)
	}
	if _, err := store.PreparePresignCandidate(ctx, binding, "compact-presign"); !errors.Is(err, ErrLifecycleHistoryCompacted) {
		t.Fatalf("compacted presign query = %v, want ErrLifecycleHistoryCompacted", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, RunSign, signSession); !errors.Is(err, ErrSessionAlreadyUsed) {
		t.Fatalf("compacted session reuse = %v, want ErrSessionAlreadyUsed", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := reopened.QueryAttemptOutcome(ctx, query); !errors.Is(err, ErrLifecycleHistoryCompacted) {
		t.Fatalf("reopened compacted attempt query = %v, want ErrLifecycleHistoryCompacted", err)
	}
	if _, err := reopened.LoadCurrentGeneration(ctx, binding.KeyID); err != nil {
		t.Fatalf("compaction damaged current generation: %v", err)
	}
}

func TestFileLifecycleStoreCompactsCutoverGraphWithoutAllowingReuse(t *testing.T) {
	ctx := context.Background()
	store := newTestFileLifecycleStore(t, t.TempDir(), []byte("cutover-compaction-passphrase"))
	source := testGenerationBinding("compact-cutover-key", "gen-1", "compact-cutover-source")
	target := testGenerationBinding(source.KeyID, "gen-2", "compact-cutover-target")
	if _, err := store.InstallInitialGeneration(ctx, source, []byte("source-secret"), nil); err != nil {
		t.Fatal(err)
	}
	sessionID := fileLifecycleSessionID(t, "compact-cutover-session")
	lease, err := store.AcquireRunLease(ctx, source, RunRefresh, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := store.BeginCutoverFromLease(ctx, lease, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitCutover(ctx, fence, []byte("target-secret"), nil); err != nil {
		t.Fatal(err)
	}
	report, err := store.CompactLifecycle(ctx, LifecycleCompactionRequest{KeyID: target.KeyID, ExpectedCurrent: target})
	if err != nil {
		t.Fatal(err)
	}
	if report.Leases != 1 || report.Cutovers != 1 || report.Generations != 1 {
		t.Fatalf("unexpected cutover compaction report: %+v", report)
	}
	if _, err := store.QueryRunLease(ctx, source, RunRefresh, sessionID); !errors.Is(err, ErrLifecycleHistoryCompacted) {
		t.Fatalf("compacted cutover lease query = %v", err)
	}
	if _, err := store.AcquireRunLease(ctx, target, RunSign, sessionID); !errors.Is(err, ErrSessionAlreadyUsed) {
		t.Fatalf("compacted cutover session reuse = %v", err)
	}
	if _, err := store.CommitCutover(ctx, fence, []byte("target-secret"), nil); !errors.Is(err, ErrLifecycleHistoryCompacted) {
		t.Fatalf("compacted cutover retry = %v", err)
	}
	if _, err := store.InstallInitialGeneration(ctx, source, []byte("replacement-secret"), nil); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("compacted source generation reuse = %v", err)
	}
	current, err := store.LoadCurrentGeneration(ctx, target.KeyID)
	if err != nil || current.Binding != target {
		t.Fatalf("current target after compaction=%+v err=%v", current.Binding, err)
	}
}

func TestFileLifecycleStoreUsesOneKDFPerOpenAndBucketedIndexes(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store := newTestFileLifecycleStore(t, directory, []byte("one-kdf-passphrase"))
	for i, keyID := range []string{"bucket-key-a", "bucket-key-b"} {
		binding := testGenerationBinding(keyID, "gen-1", keyID+"-epoch")
		if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-"+keyID), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcquireRunLease(ctx, binding, RunPresign, fileLifecycleSessionID(t, keyID)); err != nil {
			t.Fatal(err)
		}
		if got := store.kdfDerivations; got != 1 {
			t.Fatalf("operation %d caused %d KDF derivations, want one per open", i, got)
		}
	}
	root, err := loadFileLifecycleRoot(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Lineages) != 2 || len(root.Buckets) == 0 {
		t.Fatalf("root lineages=%d buckets=%d, want partitioned lineage and index refs", len(root.Lineages), len(root.Buckets))
	}
	for _, bucket := range root.Buckets {
		if len(bucket.Prefix) != 4 {
			t.Fatalf("index bucket prefix %q is not 16-bit hexadecimal", bucket.Prefix)
		}
	}
}

func TestFileLifecycleStoreRejectsRetiredManifestShape(t *testing.T) {
	directory := t.TempDir()
	// #nosec G302 -- 0700 is the required private directory mode; this is not a regular file.
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyDirectory := filepath.Join(directory, fileLifecycleKeysDirectory, fileLifecycleKeyHash(fileLifecycleGlobalKeyID))
	if err := os.MkdirAll(legacyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDirectory, fileLifecycleManifestName), []byte("retired-format"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileLifecycleStore(directory, []byte("retired-format-passphrase"), fastFileLifecycleParams)
	if store != nil || !errors.Is(err, ErrLifecycleCorrupt) {
		t.Fatalf("retired manifest open returned store=%v err=%v", store, err)
	}
}

func TestFileLifecycleStoreRejectsMissingMetadataForExistingState(t *testing.T) {
	directory := t.TempDir()
	passphrase := []byte("missing-metadata-passphrase")
	store := newTestFileLifecycleStore(t, directory, passphrase)
	binding := testGenerationBinding("missing-metadata-key", "gen-1", "missing-metadata-epoch")
	if _, err := store.InstallInitialGeneration(context.Background(), binding, []byte("generation-secret"), nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(directory, fileLifecycleMetaName)
	if err := os.Remove(metaPath); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileLifecycleStore(directory, passphrase, fastFileLifecycleParams)
	if reopened != nil || !errors.Is(err, ErrLifecycleCorrupt) {
		t.Fatalf("missing metadata open returned store=%v err=%v", reopened, err)
	}
	if _, err := os.Lstat(metaPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed open recreated missing metadata: %v", err)
	}
}
