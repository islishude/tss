package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/islishude/tss"
)

func TestMemoryLifecycleStoreReturnsDefensiveSecretSnapshots(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryLifecycleStore()
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	generationBlob := []byte("generation-secret")
	installed, err := store.InstallInitialGeneration(ctx, binding, generationBlob, []byte("generation-metadata"))
	if err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	generationBlob[0] ^= 0xff
	installed.Blob[0] ^= 0xff
	loaded, err := store.LoadCurrentGeneration(ctx, binding.KeyID)
	if err != nil {
		t.Fatalf("LoadCurrentGeneration: %v", err)
	}
	if string(loaded.Blob) != "generation-secret" {
		t.Fatal("caller mutation changed stored generation blob")
	}

	commitTestAvailablePresign(t, store, binding, "presign-1", []byte("presign-secret"), []byte("presign-metadata"), "defensive-snapshots")
	candidate, err := store.PreparePresignCandidate(ctx, binding, "presign-1")
	if err != nil {
		t.Fatalf("PreparePresignCandidate: %v", err)
	}
	candidate.Blob[0] ^= 0xff
	reloaded, err := store.PreparePresignCandidate(ctx, binding, "presign-1")
	if err != nil {
		t.Fatalf("PreparePresignCandidate second: %v", err)
	}
	if string(reloaded.Blob) != "presign-secret" {
		t.Fatal("caller mutation changed stored presign blob")
	}

	sessionID := newLifecycleSessionID(t)
	lease, err := store.AcquireRunLease(ctx, binding, RunSign, sessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	intent := SignAttemptIntent{AttemptID: "attempt-1", SessionID: sessionID, IntentDigest: testRunDigest("intent")}
	commit, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
	if err != nil {
		t.Fatalf("CommitSignAttempt: %v", err)
	}
	commit.Record.PresignMetadata[0] ^= 0xff
	queried, err := store.QueryAttemptOutcome(ctx, commit.Record.Query())
	if err != nil {
		t.Fatalf("QueryAttemptOutcome: %v", err)
	}
	if string(queried.PresignMetadata) != "presign-metadata" || string(queried.ExactOutbox) != "exact-outbox" {
		t.Fatal("caller mutation changed stored attempt recovery state")
	}
	if err := store.FinishRunLease(ctx, lease, LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease: %v", err)
	}

	for name, value := range map[string]any{
		"generation": loaded,
		"presign":    reloaded,
		"attempt":    queried,
	} {
		formatted := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(formatted, "secret") || strings.Contains(formatted, "outbox") {
			t.Fatalf("%s formatting exposed confidential state", name)
		}
	}
}

func TestMemoryLifecycleStoreTerminalAttemptClearsRecoverySecrets(t *testing.T) {
	ctx := context.Background()
	store, binding, lease, query := committedLifecycleAttempt(t)

	completed, err := store.CompleteAttempt(ctx, query, []byte("signature"))
	if err != nil {
		t.Fatalf("CompleteAttempt: %v", err)
	}
	if completed.Terminal() || len(completed.PresignMetadata) == 0 || len(completed.ExactOutbox) == 0 {
		t.Fatal("completion without durable delivery became terminal")
	}
	delivered, err := store.MarkAttemptDelivered(ctx, query, []byte("delivery-certificate"))
	if err != nil {
		t.Fatalf("MarkAttemptDelivered: %v", err)
	}
	if !delivered.Terminal() || len(delivered.PresignMetadata) == 0 || len(delivered.ExactOutbox) != 0 {
		t.Fatal("terminal attempt retained secret recovery state")
	}
	if err := store.FinishRunLease(ctx, lease, LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease: %v", err)
	}

	target := testGenerationBinding(binding.KeyID, "gen-2", "epoch-2")
	fence, err := store.BeginCutover(ctx, binding, target)
	if err != nil {
		t.Fatalf("BeginCutover after terminal attempt: %v", err)
	}
	if _, err := store.CommitCutover(ctx, fence, []byte("next-generation-secret"), nil); err != nil {
		t.Fatalf("CommitCutover: %v", err)
	}
	if _, err := store.PreparePresignCandidate(ctx, binding, query.PresignID); !errors.Is(err, ErrGenerationNotCurrent) {
		t.Fatalf("old-generation prepare got %v, want ErrGenerationNotCurrent", err)
	}
}

func TestMemoryLifecycleStoreCanceledMutationLeavesPresignAvailable(t *testing.T) {
	store := NewMemoryLifecycleStore()
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	if _, err := store.InstallInitialGeneration(context.Background(), binding, []byte("generation"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	commitTestAvailablePresign(t, store, binding, "presign-1", []byte("presign"), []byte("public-metadata"), "canceled-mutation")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	intent := SignAttemptIntent{AttemptID: "attempt-1", SessionID: newLifecycleSessionID(t), IntentDigest: testRunDigest("intent")}
	if _, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("outbox")); !errors.Is(err, context.Canceled) {
		t.Fatalf("CommitSignAttempt got %v, want context.Canceled", err)
	}
	candidate, err := store.PreparePresignCandidate(context.Background(), binding, "presign-1")
	if err != nil {
		t.Fatalf("PreparePresignCandidate after cancellation: %v", err)
	}
	if !bytes.Equal(candidate.Blob, []byte("presign")) {
		t.Fatal("canceled commit mutated available presign")
	}
}

func TestMemoryLifecycleStoreSuccessiveCutoversDoNotRetainRetiredGenerationSecrets(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryLifecycleStore()
	first := testGenerationBinding("key-1", "gen-1", "epoch-1")
	second := testGenerationBinding("key-1", "gen-2", "epoch-2")
	third := testGenerationBinding("key-1", "gen-3", "epoch-3")
	if _, err := store.InstallInitialGeneration(ctx, first, []byte("first-generation-secret"), []byte("first-metadata")); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	firstFence, err := store.BeginCutover(ctx, first, second)
	if err != nil {
		t.Fatalf("BeginCutover first: %v", err)
	}
	secondBlob := []byte("second-generation-secret")
	secondMetadata := []byte("second-metadata")
	if _, err := store.CommitCutover(ctx, firstFence, secondBlob, secondMetadata); err != nil {
		t.Fatalf("CommitCutover first: %v", err)
	}
	secondFence, err := store.BeginCutover(ctx, second, third)
	if err != nil {
		t.Fatalf("BeginCutover second: %v", err)
	}
	if _, err := store.CommitCutover(ctx, secondFence, []byte("third-generation-secret"), []byte("third-metadata")); err != nil {
		t.Fatalf("CommitCutover second: %v", err)
	}

	retired := store.generations[second]
	if retired == nil || retired.record.Status != GenerationRetired || len(retired.record.Blob) != 0 || len(retired.record.Metadata) != 0 {
		t.Fatal("retired generation retained its secret blob or metadata")
	}
	history := store.cutoversByToken[firstFence.Token]
	wantBlobDigest := sha256.Sum256(secondBlob)
	wantMetadataDigest := sha256.Sum256(secondMetadata)
	if history == nil || history.state != storedCutoverCommitted ||
		!bytes.Equal(history.targetBlobDigest, wantBlobDigest[:]) ||
		!bytes.Equal(history.targetMetadataDigest, wantMetadataDigest[:]) {
		t.Fatal("committed cutover did not retain only the target digests")
	}
}

func committedLifecycleAttempt(t *testing.T) (*MemoryLifecycleStore, GenerationBinding, RunLease, AttemptQuery) {
	t.Helper()
	ctx := context.Background()
	store := NewMemoryLifecycleStore()
	binding := testGenerationBinding("key-1", "gen-1", "epoch-1")
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	commitTestAvailablePresign(t, store, binding, "presign-1", []byte("presign-secret"), []byte("public-metadata"), "committed-attempt")
	sessionID := newLifecycleSessionID(t)
	lease, err := store.AcquireRunLease(ctx, binding, RunSign, sessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	intent := SignAttemptIntent{AttemptID: "attempt-1", SessionID: sessionID, IntentDigest: testRunDigest("intent")}
	commit, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
	if err != nil {
		t.Fatalf("CommitSignAttempt: %v", err)
	}
	return store, binding, lease, commit.Record.Query()
}

func newLifecycleSessionID(t *testing.T) tss.SessionID {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return sessionID
}
