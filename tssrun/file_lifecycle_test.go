package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/islishude/tss"
)

var fastFileLifecycleParams = &tss.PassphraseParams{Time: 1, Memory: 1024, Threads: 1}

func TestFileLifecycleStoreReopensAttemptAndCutoverState(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("file-lifecycle-reopen-passphrase")
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	store := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), []byte("generation-metadata")); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close initial store: %v", err)
	}

	store = newTestFileLifecycleStore(t, directory, passphrase)
	loaded, err := store.LoadCurrentGeneration(ctx, binding.KeyID)
	if err != nil || loaded.Binding != binding || string(loaded.Blob) != "generation-secret" {
		t.Fatalf("LoadCurrentGeneration binding=%v blob=%q err=%v", loaded.Binding, loaded.Blob, err)
	}
	commitTestAvailablePresign(t, store, binding, "presign-1", []byte("presign-secret"), []byte("presign-metadata"), "reopen")
	sessionID := fileLifecycleSessionID(t, "reopen-attempt")
	lease, err := store.AcquireRunLease(ctx, binding, RunSign, sessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	intent := SignAttemptIntent{AttemptID: "attempt-1", SessionID: sessionID, IntentDigest: testRunDigest("intent")}
	commit, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
	if err != nil {
		t.Fatalf("CommitSignAttempt: %v", err)
	}
	query := commit.Record.Query()
	if err := store.Close(); err != nil {
		t.Fatalf("Close attempt store: %v", err)
	}

	store = newTestFileLifecycleStore(t, directory, passphrase)
	recovered, err := store.QueryAttemptOutcome(ctx, query)
	if err != nil || string(recovered.PresignMetadata) != "presign-metadata" || string(recovered.ExactOutbox) != "exact-outbox" {
		t.Fatalf("QueryAttemptOutcome metadata=%q outbox=%q err=%v", recovered.PresignMetadata, recovered.ExactOutbox, err)
	}
	if _, err := store.CompleteAttempt(ctx, query, []byte("completion")); err != nil {
		t.Fatalf("CompleteAttempt: %v", err)
	}
	if _, err := store.MarkAttemptDelivered(ctx, query, []byte("delivery")); err != nil {
		t.Fatalf("MarkAttemptDelivered: %v", err)
	}
	if err := store.FinishRunLease(ctx, lease, LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease: %v", err)
	}
	target := testGenerationBinding(binding.KeyID, "gen-2", "epoch-2")
	fence, err := store.BeginCutover(ctx, binding, target)
	if err != nil {
		t.Fatalf("BeginCutover: %v", err)
	}
	if _, err := store.CommitCutover(ctx, fence, []byte("target-secret"), []byte("target-metadata")); err != nil {
		t.Fatalf("CommitCutover: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close cutover store: %v", err)
	}

	store = newTestFileLifecycleStore(t, directory, passphrase)
	current, err := store.LoadCurrentGeneration(ctx, binding.KeyID)
	if err != nil || current.Binding != target || string(current.Blob) != "target-secret" {
		t.Fatalf("reopened target binding=%v blob=%q err=%v", current.Binding, current.Blob, err)
	}
	terminal, err := store.QueryAttemptOutcome(ctx, query)
	if err != nil || !terminal.Terminal() || len(terminal.PresignMetadata) == 0 || len(terminal.ExactOutbox) != 0 {
		t.Fatalf("reopened terminal attempt terminal=%v err=%v", terminal.Terminal(), err)
	}
}

func TestFileLifecycleStoreCrashBoundariesResolveByExactQuery(t *testing.T) {
	for _, tc := range []struct {
		point     FileLifecycleFaultPoint
		committed bool
	}{
		{point: FileLifecycleFaultAfterBlobWrite},
		{point: FileLifecycleFaultAfterBlobSync},
		{point: FileLifecycleFaultAfterManifestWrite},
		{point: FileLifecycleFaultAfterManifestSync},
		{point: FileLifecycleFaultAfterManifestRename, committed: true},
		{point: FileLifecycleFaultAfterManifestDirectorySync, committed: true},
	} {
		t.Run(string(tc.point), func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("file-lifecycle-crash-passphrase")
			binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
			intent := SignAttemptIntent{
				AttemptID:    "attempt-1",
				SessionID:    fileLifecycleSessionID(t, "crash-attempt"),
				IntentDigest: testRunDigest("intent"),
			}
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			commitTestAvailablePresign(t, setup, binding, "presign-1", []byte("presign-secret"), []byte("public-metadata"), "attempt-crash")
			if _, err := setup.AcquireRunLease(ctx, binding, RunSign, intent.SessionID); err != nil {
				t.Fatalf("AcquireRunLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated process crash")
			var once sync.Once
			faultStore, err := NewFileLifecycleStore(directory, passphrase, fastFileLifecycleParams, WithFileLifecycleFaultInjector(func(point FileLifecycleFaultPoint) error {
				if point != tc.point {
					return nil
				}
				var result error
				once.Do(func() { result = injected })
				return result
			}))
			if err != nil {
				t.Fatalf("NewFileLifecycleStore fault store: %v", err)
			}
			_, err = faultStore.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
			if !errors.Is(err, ErrAttemptOutcomeUnknown) || !errors.Is(err, injected) {
				t.Fatalf("CommitSignAttempt got %v, want injected outcome unknown", err)
			}
			var unknown *AttemptOutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("CommitSignAttempt error type=%T, want AttemptOutcomeUnknownError", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			record, queryErr := reopened.QueryAttemptOutcome(ctx, unknown.Query)
			if tc.committed {
				if queryErr != nil || string(record.ExactOutbox) != "exact-outbox" {
					t.Fatalf("post-rename query outbox=%q err=%v", record.ExactOutbox, queryErr)
				}
				if _, err := reopened.PreparePresignCandidate(ctx, binding, "presign-1"); !errors.Is(err, ErrPresignUnavailable) {
					t.Fatalf("committed crash left presign available: %v", err)
				}
			} else {
				if !errors.Is(queryErr, ErrAttemptNotFound) {
					t.Fatalf("pre-rename query got %v, want ErrAttemptNotFound", queryErr)
				}
				if _, err := reopened.PreparePresignCandidate(ctx, binding, "presign-1"); err != nil {
					t.Fatalf("pre-rename crash consumed presign: %v", err)
				}
				retry, err := reopened.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
				if err != nil || retry.Status != AttemptCreated {
					t.Fatalf("exact retry status=%v err=%v", retry.Status, err)
				}
			}
		})
	}
}

func TestFileLifecycleStoreLeaseEffectCrashAtomicity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		point     FileLifecycleFaultPoint
		committed bool
	}{
		{name: "before rename", point: FileLifecycleFaultAfterManifestSync},
		{name: "after rename", point: FileLifecycleFaultAfterManifestRename, committed: true},
	} {
		t.Run("presign/"+tc.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("presign-lease-effect-crash")
			binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			lease, err := setup.AcquireRunLease(ctx, binding, RunPresign, fileLifecycleSessionID(t, "crash-presign-lease"))
			if err != nil {
				t.Fatalf("AcquireRunLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated presign commit crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			err = faultStore.CommitAvailablePresignFromLease(ctx, lease, "presign-1", []byte("presign-secret"), []byte("public-metadata"))
			if !errors.Is(err, injected) {
				t.Fatalf("CommitAvailablePresignFromLease got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			candidate, prepareErr := reopened.PreparePresignCandidate(ctx, binding, "presign-1")
			if tc.committed {
				if prepareErr != nil || string(candidate.Blob) != "presign-secret" {
					t.Fatalf("post-rename candidate blob=%q err=%v", candidate.Blob, prepareErr)
				}
			} else if !errors.Is(prepareErr, ErrPresignUnavailable) {
				t.Fatalf("pre-rename prepare got %v, want ErrPresignUnavailable", prepareErr)
			}
			if err := reopened.CommitAvailablePresignFromLease(ctx, lease, "presign-1", []byte("presign-secret"), []byte("public-metadata")); err != nil {
				t.Fatalf("exact retry after crash: %v", err)
			}
		})

		t.Run("refresh-marker/"+tc.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("refresh-marker-crash")
			binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			lease, err := setup.AcquireRunLease(ctx, binding, RunRefresh, fileLifecycleSessionID(t, "crash-refresh-marker"))
			if err != nil {
				t.Fatalf("AcquireRunLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated refresh marker crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			_, err = faultStore.MarkProtocolRefreshFailed(ctx, lease, "protocol verification failed")
			if !errors.Is(err, injected) {
				t.Fatalf("MarkProtocolRefreshFailed got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			_, probeErr := reopened.AcquireRunLease(ctx, binding, RunRefresh, fileLifecycleSessionID(t, "refresh-marker-probe"))
			if tc.committed {
				if !errors.Is(probeErr, ErrRefreshDisabled) {
					t.Fatalf("post-rename refresh probe got %v, want ErrRefreshDisabled", probeErr)
				}
			} else if !errors.Is(probeErr, ErrRunLeaseConflict) {
				t.Fatalf("pre-rename refresh probe got %v, want ErrRunLeaseConflict", probeErr)
			}
			if _, err := reopened.MarkProtocolRefreshFailed(ctx, lease, "protocol verification failed"); err != nil {
				t.Fatalf("exact marker retry after crash: %v", err)
			}
		})

		t.Run("cutover-from-lease/"+tc.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("cutover-lease-effect-crash")
			source := testGenerationBinding("key-1", "gen-1", "epoch-1")
			target := testGenerationBinding(source.KeyID, "gen-2", "epoch-2")
			alternate := testGenerationBinding(source.KeyID, "gen-3", "epoch-3")
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, source, []byte("generation-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			lease, err := setup.AcquireRunLease(ctx, source, RunRefresh, fileLifecycleSessionID(t, "crash-cutover-lease"))
			if err != nil {
				t.Fatalf("AcquireRunLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated cutover fence crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			_, err = faultStore.BeginCutoverFromLease(ctx, lease, target)
			if !errors.Is(err, injected) {
				t.Fatalf("BeginCutoverFromLease got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			alternateFence, alternateErr := reopened.BeginCutoverFromLease(ctx, lease, alternate)
			if tc.committed {
				if !errors.Is(alternateErr, ErrRunLeaseConflict) {
					t.Fatalf("post-rename alternate target got %v, want ErrRunLeaseConflict", alternateErr)
				}
				fence, err := reopened.BeginCutoverFromLease(ctx, lease, target)
				if err != nil {
					t.Fatalf("exact target retry: %v", err)
				}
				if err := reopened.AbortCutover(ctx, fence, "crash test cleanup"); err != nil {
					t.Fatalf("AbortCutover: %v", err)
				}
			} else {
				if alternateErr != nil {
					t.Fatalf("pre-rename alternate target: %v", alternateErr)
				}
				if _, err := reopened.BeginCutoverFromLease(ctx, lease, target); !errors.Is(err, ErrRunLeaseConflict) {
					t.Fatalf("pre-rename losing target got %v, want ErrRunLeaseConflict", err)
				}
				if err := reopened.AbortCutover(ctx, alternateFence, "crash test cleanup"); err != nil {
					t.Fatalf("AbortCutover alternate: %v", err)
				}
			}
		})

		t.Run("child-generation/"+tc.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("child-generation-crash")
			parent := testGenerationBinding("parent-key", "gen-1", "epoch-1")
			child := testGenerationBinding("child-key", "child-gen-1", "child-epoch-1")
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, parent, []byte("parent-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			lease, err := setup.AcquireRunLease(ctx, parent, RunChildDerivation, fileLifecycleSessionID(t, "crash-child-generation"))
			if err != nil {
				t.Fatalf("AcquireRunLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated child generation crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			_, err = faultStore.CommitInitialGenerationFromLease(ctx, lease, child, []byte("child-secret"), []byte("child-metadata"))
			if !errors.Is(err, injected) {
				t.Fatalf("CommitInitialGenerationFromLease got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			loaded, loadErr := reopened.LoadCurrentGeneration(ctx, child.KeyID)
			if tc.committed {
				if loadErr != nil || loaded.Binding != child {
					t.Fatalf("post-rename child binding=%v err=%v", loaded.Binding, loadErr)
				}
			} else if !errors.Is(loadErr, ErrGenerationNotCurrent) {
				t.Fatalf("pre-rename child load got %v, want ErrGenerationNotCurrent", loadErr)
			}
			if _, err := reopened.CommitInitialGenerationFromLease(ctx, lease, child, []byte("child-secret"), []byte("child-metadata")); err != nil {
				t.Fatalf("exact child retry after crash: %v", err)
			}
			currentParent, err := reopened.LoadCurrentGeneration(ctx, parent.KeyID)
			if err != nil || currentParent.Binding != parent || string(currentParent.Blob) != "parent-secret" {
				t.Fatalf("parent changed binding=%v blob=%q err=%v", currentParent.Binding, currentParent.Blob, err)
			}
		})
	}
}

func TestFileLifecycleStoreCutoverCommitCrashAtomicity(t *testing.T) {
	for _, tc := range []struct {
		point     FileLifecycleFaultPoint
		committed bool
	}{
		{point: FileLifecycleFaultAfterBlobWrite},
		{point: FileLifecycleFaultAfterBlobSync},
		{point: FileLifecycleFaultAfterManifestWrite},
		{point: FileLifecycleFaultAfterManifestSync},
		{point: FileLifecycleFaultAfterManifestRename, committed: true},
		{point: FileLifecycleFaultAfterManifestDirectorySync, committed: true},
	} {
		t.Run(string(tc.point), func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("cutover-commit-crash")
			source := testGenerationBinding("key-1", "gen-1", "epoch-1")
			target := testGenerationBinding(source.KeyID, "gen-2", "epoch-2")
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, source, []byte("source-secret"), []byte("source-metadata")); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			commitTestAvailablePresign(t, setup, source, "presign-old", []byte("presign-secret"), []byte("public-metadata"), "cutover-crash")
			fence, err := setup.BeginCutover(ctx, source, target)
			if err != nil {
				t.Fatalf("BeginCutover: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated cutover commit crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			_, err = faultStore.CommitCutover(ctx, fence, []byte("target-secret"), []byte("target-metadata"))
			if !errors.Is(err, injected) {
				t.Fatalf("CommitCutover got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			current, err := reopened.LoadCurrentGeneration(ctx, source.KeyID)
			if err != nil {
				t.Fatalf("LoadCurrentGeneration: %v", err)
			}
			if tc.committed {
				if current.Binding != target || string(current.Blob) != "target-secret" {
					t.Fatalf("post-rename current binding=%v blob=%q", current.Binding, current.Blob)
				}
				if err := reopened.BurnPresign(ctx, source, "presign-old", "verify tombstone before retry"); !errors.Is(err, ErrPresignBurned) {
					t.Fatalf("post-rename source presign got %v, want ErrPresignBurned", err)
				}
			} else {
				if current.Binding != source || string(current.Blob) != "source-secret" {
					t.Fatalf("pre-rename current binding=%v blob=%q", current.Binding, current.Blob)
				}
				state, err := fileLifecycleStoredPresignState(ctx, reopened, source.KeyID, "presign-old")
				if err != nil || state != storedPresignAvailable {
					t.Fatalf("pre-rename source presign state=%v err=%v, want available", state, err)
				}
			}
			if _, err := reopened.CommitCutover(ctx, fence, []byte("target-secret"), []byte("target-metadata")); err != nil {
				t.Fatalf("exact cutover retry after crash: %v", err)
			}
			if err := reopened.BurnPresign(ctx, source, "presign-old", "verify tombstone"); !errors.Is(err, ErrPresignBurned) {
				t.Fatalf("source presign after cutover got %v, want ErrPresignBurned", err)
			}
		})
	}
}

func TestFileLifecycleStoreReshareReceiverCrashAtomicity(t *testing.T) {
	for _, tc := range []struct {
		point     FileLifecycleFaultPoint
		committed bool
	}{
		{point: FileLifecycleFaultAfterBlobWrite},
		{point: FileLifecycleFaultAfterBlobSync},
		{point: FileLifecycleFaultAfterManifestWrite},
		{point: FileLifecycleFaultAfterManifestSync},
		{point: FileLifecycleFaultAfterManifestRename, committed: true},
		{point: FileLifecycleFaultAfterManifestDirectorySync, committed: true},
	} {
		t.Run(string(tc.point), func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("receiver-install-crash")
			source := testGenerationBinding("receiver-key", "source-gen", "source-epoch")
			target := testGenerationBinding(source.KeyID, "target-gen", "target-epoch")
			anchor := ReshareReceiverAnchor{
				Source:              source,
				TargetKeyGeneration: target.KeyGeneration,
				SessionID:           fileLifecycleSessionID(t, "receiver-crash"),
				PlanDigest:          testRunDigest("receiver-plan"),
				SourceEpochDigest:   testRunDigest("receiver-source-epoch"),
			}
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			lease, err := setup.AcquireReshareReceiverLease(ctx, anchor)
			if err != nil {
				t.Fatalf("AcquireReshareReceiverLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated receiver install crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			_, err = faultStore.CommitInitialGenerationFromReshareLease(ctx, lease, target, []byte("receiver-secret"), []byte("receiver-metadata"))
			if !errors.Is(err, injected) {
				t.Fatalf("CommitInitialGenerationFromReshareLease got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			current, loadErr := reopened.LoadCurrentGeneration(ctx, source.KeyID)
			if tc.committed {
				if loadErr != nil || current.Binding != target || string(current.Blob) != "receiver-secret" {
					t.Fatalf("post-rename receiver binding=%v blob=%q err=%v", current.Binding, current.Blob, loadErr)
				}
			} else if !errors.Is(loadErr, ErrGenerationNotCurrent) {
				t.Fatalf("pre-rename receiver load got %v, want ErrGenerationNotCurrent", loadErr)
			}
			if _, err := reopened.CommitInitialGenerationFromReshareLease(ctx, lease, target, []byte("receiver-secret"), []byte("receiver-metadata")); err != nil {
				t.Fatalf("exact receiver retry after crash: %v", err)
			}
		})
	}
}

func TestFileLifecycleStoreRetirementCrashAtomicity(t *testing.T) {
	for _, tc := range []struct {
		point     FileLifecycleFaultPoint
		committed bool
	}{
		{point: FileLifecycleFaultAfterManifestWrite},
		{point: FileLifecycleFaultAfterManifestSync},
		{point: FileLifecycleFaultAfterManifestRename, committed: true},
		{point: FileLifecycleFaultAfterManifestDirectorySync, committed: true},
	} {
		t.Run(string(tc.point), func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("retirement-crash")
			source := testGenerationBinding("retiring-key", "gen-1", "epoch-1")
			target := testGenerationBinding(source.KeyID, "gen-2", "epoch-2")
			unrelated := testGenerationBinding("unrelated-key", "gen-1", "epoch-1")
			setup := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := setup.InstallInitialGeneration(ctx, source, []byte("source-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration source: %v", err)
			}
			commitTestAvailablePresign(t, setup, source, "source-presign", []byte("source-presign-secret"), []byte("source-presign-metadata"), "retirement-source")
			if _, err := setup.InstallInitialGeneration(ctx, unrelated, []byte("unrelated-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration unrelated: %v", err)
			}
			commitTestAvailablePresign(t, setup, unrelated, "unrelated-presign", []byte("unrelated-presign-secret"), []byte("unrelated-presign-metadata"), "retirement-unrelated")
			lease, err := setup.AcquireRunLease(ctx, source, RunReshare, fileLifecycleSessionID(t, "retirement-crash"))
			if err != nil {
				t.Fatalf("AcquireRunLease: %v", err)
			}
			_ = setup.Close()

			injected := errors.New("simulated retirement crash")
			faultStore := newFaultFileLifecycleStore(t, directory, passphrase, tc.point, injected)
			err = faultStore.CommitRetirementFromLease(ctx, lease, target)
			if !errors.Is(err, injected) {
				t.Fatalf("CommitRetirementFromLease got %v, want injected error", err)
			}
			_ = faultStore.Close()

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			current, loadErr := reopened.LoadCurrentGeneration(ctx, source.KeyID)
			if tc.committed {
				if !errors.Is(loadErr, ErrGenerationNotCurrent) {
					t.Fatalf("post-rename retired source load got %v, want ErrGenerationNotCurrent", loadErr)
				}
				if err := reopened.BurnPresign(ctx, source, "source-presign", "verify retirement before retry"); !errors.Is(err, ErrPresignBurned) {
					t.Fatalf("post-rename retired presign got %v, want ErrPresignBurned", err)
				}
			} else {
				if loadErr != nil || current.Binding != source {
					t.Fatalf("pre-rename source binding=%v err=%v", current.Binding, loadErr)
				}
				if _, err := reopened.PreparePresignCandidate(ctx, source, "source-presign"); err != nil {
					t.Fatalf("pre-rename retirement consumed source presign: %v", err)
				}
			}
			if err := reopened.CommitRetirementFromLease(ctx, lease, target); err != nil {
				t.Fatalf("exact retirement retry after crash: %v", err)
			}
			if err := reopened.BurnPresign(ctx, source, "source-presign", "verify retirement"); !errors.Is(err, ErrPresignBurned) {
				t.Fatalf("source presign after retirement got %v, want ErrPresignBurned", err)
			}
			if _, err := reopened.PreparePresignCandidate(ctx, unrelated, "unrelated-presign"); err != nil {
				t.Fatalf("retirement burned unrelated presign: %v", err)
			}
		})
	}
}

func TestFileLifecycleStoreCiphertextsAreImmutableAndRedacted(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store := newTestFileLifecycleStore(t, directory, []byte("immutable-ciphertext-passphrase"))
	binding := testGenerationBinding("public-key-id", "gen-1", "epoch-1")
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-plaintext-secret"), []byte("generation-plaintext-metadata")); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	before := lifecycleRegularFiles(t, directory)
	commitTestAvailablePresign(t, store, binding, "public-presign-id", []byte("presign-plaintext-secret"), []byte("presign-plaintext-metadata"), "encrypted-blobs")
	after := lifecycleRegularFiles(t, directory)
	for path, content := range before {
		if strings.HasSuffix(path, fileLifecycleManifestName) || strings.HasSuffix(path, ".lock") {
			continue
		}
		if updated, ok := after[path]; !ok || !bytes.Equal(content, updated) {
			t.Fatalf("immutable blob changed or disappeared: %s", path)
		}
	}
	for path, content := range after {
		for _, secret := range [][]byte{
			[]byte("generation-plaintext-secret"),
			[]byte("generation-plaintext-metadata"),
			[]byte("presign-plaintext-secret"),
			[]byte("presign-plaintext-metadata"),
		} {
			if bytes.Contains(content, secret) {
				t.Fatalf("plaintext appeared in lifecycle file %s", path)
			}
		}
		if strings.Contains(path, binding.KeyID) || strings.Contains(path, "public-presign-id") {
			t.Fatalf("public identifiers leaked into lifecycle path %s", path)
		}
	}
}

func TestFileLifecycleStoreConcurrentInstancesClaimOnce(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("concurrent-file-store-passphrase")
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	setup := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := setup.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	commitTestAvailablePresign(t, setup, binding, "presign-1", []byte("presign"), []byte("public-metadata"), "multi-process-attempt")
	intents := []SignAttemptIntent{
		{AttemptID: "attempt-1", SessionID: fileLifecycleSessionID(t, "instance-1"), IntentDigest: testRunDigest("intent-1")},
		{AttemptID: "attempt-2", SessionID: fileLifecycleSessionID(t, "instance-2"), IntentDigest: testRunDigest("intent-2")},
	}
	for _, intent := range intents {
		if _, err := setup.AcquireRunLease(ctx, binding, RunSign, intent.SessionID); err != nil {
			t.Fatalf("AcquireRunLease: %v", err)
		}
	}
	_ = setup.Close()
	stores := []*FileLifecycleStore{
		newTestFileLifecycleStore(t, directory, passphrase),
		newTestFileLifecycleStore(t, directory, passphrase),
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, err := stores[index].CommitSignAttempt(ctx, binding, "presign-1", intents[index], []byte("outbox-"+intents[index].AttemptID))
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	var created, conflicts int
	for err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrAttemptConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent instance error: %v", err)
		}
	}
	if created != 1 || conflicts != 1 {
		t.Fatalf("concurrent instance claims created=%d conflicts=%d, want one each", created, conflicts)
	}
}

func TestFileLifecycleStoreConcurrentLineagesPreserveGlobalManifest(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("concurrent-lineage-file-store-passphrase")
	bindings := []GenerationBinding{
		testGenerationBinding("key-a", "gen-1", "epoch-a"),
		testGenerationBinding("key-b", "gen-1", "epoch-b"),
	}
	stores := []*FileLifecycleStore{
		newTestFileLifecycleStore(t, directory, passphrase),
		newTestFileLifecycleStore(t, directory, passphrase),
	}
	start := make(chan struct{})
	errs := make(chan error, len(stores))
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, err := stores[index].InstallInitialGeneration(ctx, bindings[index], []byte("secret-"+bindings[index].KeyID), nil)
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent lineage install: %v", err)
		}
	}

	reopened := newTestFileLifecycleStore(t, directory, passphrase)
	for _, binding := range bindings {
		record, err := reopened.LoadCurrentGeneration(ctx, binding.KeyID)
		if err != nil || record.Binding != binding || string(record.Blob) != "secret-"+binding.KeyID {
			t.Fatalf("lineage %q binding=%v blob=%q err=%v", binding.KeyID, record.Binding, record.Blob, err)
		}
	}
	for _, lockID := range []string{
		"manifest:" + fileLifecycleGlobalKeyID,
		"lineage:" + bindings[0].KeyID,
		"lineage:" + bindings[1].KeyID,
	} {
		path := filepath.Join(directory, fileLifecycleLocksDirectory, fileLifecycleKeyHash(lockID)+".lock")
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("OS lock %q info=%v err=%v", lockID, info, err)
		}
	}
}

func TestFileLifecycleStoreReopenRemovesOrphanArtifacts(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("orphan-recovery-passphrase")
	binding := testGenerationBinding("orphan-key", "gen-1", "epoch-1")
	store := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	_ = store.Close()

	referencedPath := fileLifecycleTestBlobPaths(t, directory, 1)[0]
	// #nosec G304 G703 -- referencedPath is enumerated beneath the test-owned
	// private lifecycle directory.
	ciphertext, err := os.ReadFile(referencedPath)
	if err != nil {
		t.Fatalf("ReadFile referenced blob: %v", err)
	}
	keyDirectory := filepath.Dir(filepath.Dir(referencedPath))
	orphanPath := filepath.Join(filepath.Dir(referencedPath), strings.Repeat("0", fileLifecycleBlobIDBytes*2)+".enc")
	if orphanPath == referencedPath {
		orphanPath = filepath.Join(filepath.Dir(referencedPath), strings.Repeat("1", fileLifecycleBlobIDBytes*2)+".enc")
	}
	// #nosec G304 G703 -- orphanPath is a fixed valid blob filename beneath the
	// test-owned private blob directory.
	if err := os.WriteFile(orphanPath, ciphertext, 0o600); err != nil {
		t.Fatalf("WriteFile orphan blob: %v", err)
	}
	temporaryPath := filepath.Join(keyDirectory, ".manifest-recovery.tmp")
	// #nosec G304 G703 -- temporaryPath is a fixed store temporary filename
	// beneath the test-owned private key directory.
	if err := os.WriteFile(temporaryPath, ciphertext, 0o600); err != nil {
		t.Fatalf("WriteFile stale manifest temporary: %v", err)
	}

	reopened := newTestFileLifecycleStore(t, directory, passphrase)
	loaded, err := reopened.LoadCurrentGeneration(ctx, binding.KeyID)
	if err != nil || loaded.Binding != binding || string(loaded.Blob) != "generation-secret" {
		t.Fatalf("LoadCurrentGeneration binding=%v blob=%q err=%v", loaded.Binding, loaded.Blob, err)
	}
	for _, path := range []string{orphanPath, temporaryPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphan artifact %s survived reopen: %v", path, err)
		}
	}
}

const fileLifecycleWorkerDirectoryEnv = "TSSRUN_FILE_LIFECYCLE_WORKER_DIRECTORY"

func TestFileLifecycleStoreCrossProcessAdvisoryLock(t *testing.T) {
	if os.Getenv(fileLifecycleWorkerDirectoryEnv) != "" {
		t.Skip("parent-only test")
	}
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("cross-process-file-store-passphrase")
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	setup := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := setup.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	commitTestAvailablePresign(t, setup, binding, "presign-1", []byte("presign"), []byte("public-metadata"), "multi-process-cutover")
	sessions := []tss.SessionID{
		fileLifecycleSessionID(t, "process-1"),
		fileLifecycleSessionID(t, "process-2"),
	}
	for _, sessionID := range sessions {
		if _, err := setup.AcquireRunLease(ctx, binding, RunSign, sessionID); err != nil {
			t.Fatalf("AcquireRunLease: %v", err)
		}
	}
	_ = setup.Close()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	type worker struct {
		command *exec.Cmd
		output  bytes.Buffer
		stderr  bytes.Buffer
	}
	workers := make([]worker, 2)
	for i := range workers {
		// #nosec G204 -- executable comes from os.Executable and the only
		// argument is a fixed test selector.
		command := exec.Command(executable, "-test.run=^TestFileLifecycleStoreCrossProcessWorker$")
		command.Env = append(os.Environ(),
			fileLifecycleWorkerDirectoryEnv+"="+directory,
			"TSSRUN_FILE_LIFECYCLE_WORKER_ATTEMPT=attempt-"+fmt.Sprint(i+1),
			"TSSRUN_FILE_LIFECYCLE_WORKER_SESSION="+sessions[i].String(),
			"TSSRUN_FILE_LIFECYCLE_WORKER_INTENT=intent-"+fmt.Sprint(i+1),
		)
		workers[i].command = command
		command.Stdout = &workers[i].output
		command.Stderr = &workers[i].stderr
		if err := command.Start(); err != nil {
			t.Fatalf("start worker %d: %v", i, err)
		}
	}
	for i := range workers {
		if err := workers[i].command.Wait(); err != nil {
			t.Fatalf("worker %d: %v\nstdout: %s\nstderr: %s", i, err, workers[i].output.String(), workers[i].stderr.String())
		}
	}
	combined := workers[0].output.String() + workers[1].output.String()
	if strings.Count(combined, "RESULT_CREATED") != 1 || strings.Count(combined, "RESULT_CONFLICT") != 1 {
		t.Fatalf("cross-process results:\n%s", combined)
	}
}

func TestFileLifecycleStoreCrossProcessWorker(t *testing.T) {
	directory := os.Getenv(fileLifecycleWorkerDirectoryEnv)
	if directory == "" {
		t.Skip("worker-only test")
	}
	attemptID := os.Getenv("TSSRUN_FILE_LIFECYCLE_WORKER_ATTEMPT")
	intentLabel := os.Getenv("TSSRUN_FILE_LIFECYCLE_WORKER_INTENT")
	var sessionID tss.SessionID
	if err := sessionID.UnmarshalText([]byte(os.Getenv("TSSRUN_FILE_LIFECYCLE_WORKER_SESSION"))); err != nil {
		t.Fatalf("parse worker session: %v", err)
	}
	store := newTestFileLifecycleStore(t, directory, []byte("cross-process-file-store-passphrase"))
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	intent := SignAttemptIntent{AttemptID: attemptID, SessionID: sessionID, IntentDigest: testRunDigest(intentLabel)}
	_, err := store.CommitSignAttempt(context.Background(), binding, "presign-1", intent, []byte("outbox-"+attemptID))
	switch {
	case err == nil:
		_, _ = fmt.Fprintln(os.Stdout, "RESULT_CREATED")
	case errors.Is(err, ErrAttemptConflict):
		_, _ = fmt.Fprintln(os.Stdout, "RESULT_CONFLICT")
	default:
		t.Fatalf("CommitSignAttempt: %v", err)
	}
}

func TestFileLifecycleStoreRejectsWrongPassphraseAndUseAfterClose(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	store := newTestFileLifecycleStore(t, directory, []byte("correct-passphrase"))
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	_ = store.Close()
	if _, err := store.LoadCurrentGeneration(ctx, binding.KeyID); !errors.Is(err, ErrFileLifecycleStoreClosed) {
		t.Fatalf("use after close got %v, want ErrFileLifecycleStoreClosed", err)
	}
	wrong := newTestFileLifecycleStore(t, directory, []byte("wrong-passphrase"))
	if _, err := wrong.LoadCurrentGeneration(ctx, binding.KeyID); !errors.Is(err, ErrLifecycleCorrupt) {
		t.Fatalf("wrong passphrase got %v, want ErrLifecycleCorrupt", err)
	}
}

func newTestFileLifecycleStore(t *testing.T, directory string, passphrase []byte, opts ...FileLifecycleStoreOption) *FileLifecycleStore {
	t.Helper()
	// #nosec G302 G703 -- 0700 is the required private directory mode; G302's 0600
	// recommendation applies to regular files, not traversable directories.
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod lifecycle test directory: %v", err)
	}
	store, err := NewFileLifecycleStore(directory, passphrase, fastFileLifecycleParams, opts...)
	if err != nil {
		t.Fatalf("NewFileLifecycleStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close FileLifecycleStore: %v", err)
		}
	})
	return store
}

func newFaultFileLifecycleStore(t *testing.T, directory string, passphrase []byte, point FileLifecycleFaultPoint, injected error) *FileLifecycleStore {
	t.Helper()
	var once sync.Once
	return newTestFileLifecycleStore(t, directory, passphrase, WithFileLifecycleFaultInjector(func(got FileLifecycleFaultPoint) error {
		if got != point {
			return nil
		}
		var err error
		once.Do(func() { err = injected })
		return err
	}))
}

func fileLifecycleSessionID(t *testing.T, label string) tss.SessionID {
	t.Helper()
	digest := sha256.Sum256([]byte(label))
	sessionID, err := tss.NewSessionID(bytes.NewReader(digest[:]))
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return sessionID
}

func fileLifecycleStoredPresignState(ctx context.Context, store *FileLifecycleStore, keyID, presignID string) (storedPresignState, error) {
	return readFileLifecycleState(ctx, store, []string{keyID}, func(memory *MemoryLifecycleStore) (storedPresignState, error) {
		presign := memory.presigns[presignID]
		if presign == nil {
			return 0, ErrPresignUnavailable
		}
		return presign.state, nil
	})
}

func lifecycleRegularFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		// #nosec G304 G122 -- path is supplied by WalkDir beneath the test-owned
		// temporary lifecycle root.
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = content
		return nil
	})
	if err != nil {
		t.Fatalf("walk lifecycle files: %v", err)
	}
	return files
}
