package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

func runLifecycleStore(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	t.Helper()
	t.Run("GenerationAndLeaseFences", func(t *testing.T) {
		testGenerationAndLeaseFences(t, newStore)
	})
	t.Run("AttemptAtomicityAndUnknownOutcome", func(t *testing.T) {
		testAttemptAtomicityAndUnknownOutcome(t, newStore)
	})
	t.Run("ConcurrentPresignClaim", func(t *testing.T) {
		testConcurrentPresignClaim(t, newStore)
	})
	t.Run("ConcurrentExactAttemptRetry", func(t *testing.T) {
		testConcurrentExactAttemptRetry(t, newStore)
	})
	t.Run("AttemptProgressAndCutover", func(t *testing.T) {
		testAttemptProgressAndCutover(t, newStore)
	})
	t.Run("AbortAndBurn", func(t *testing.T) {
		testAbortAndBurn(t, newStore)
	})
	t.Run("ConcurrentLeaseAndCutoverFence", func(t *testing.T) {
		testConcurrentLeaseAndCutoverFence(t, newStore)
	})
	t.Run("ConcurrentAttemptAndCutoverFence", func(t *testing.T) {
		testConcurrentAttemptAndCutoverFence(t, newStore)
	})
	t.Run("LeaseCommittedPresign", func(t *testing.T) {
		testLeaseCommittedPresign(t, newStore)
	})
	t.Run("RefreshFailureMarker", func(t *testing.T) {
		testRefreshFailureMarker(t, newStore)
	})
	t.Run("CutoverFromLease", func(t *testing.T) {
		testCutoverFromLease(t, newStore)
	})
	t.Run("ChildGenerationFromLease", func(t *testing.T) {
		testChildGenerationFromLease(t, newStore)
	})
	t.Run("ReshareReceiverGeneration", func(t *testing.T) {
		testReshareReceiverGeneration(t, newStore)
	})
	t.Run("ReshareRetirementAndRejoin", func(t *testing.T) {
		testReshareRetirementAndRejoin(t, newStore)
	})
}

func testGenerationAndLeaseFences(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store := newStore(t)
	binding := generationBinding("key-1", "gen-1", "epoch-1")
	invalid := binding
	invalid.EpochID = tssrun.EpochID{}
	if _, err := store.InstallInitialGeneration(ctx, invalid, []byte("generation"), nil); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("zero epoch install got %v, want ErrInvalidLifecycleRecord", err)
	}
	input := []byte("generation-secret")
	installed, err := store.InstallInitialGeneration(ctx, binding, input, []byte("generation-metadata"))
	if err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	input[0] ^= 0xff
	installed.Blob[0] ^= 0xff
	loaded, err := store.LoadCurrentGeneration(ctx, binding.KeyID)
	if err != nil {
		t.Fatalf("LoadCurrentGeneration: %v", err)
	}
	if string(loaded.Blob) != "generation-secret" || loaded.Binding != binding || loaded.Status != tssrun.GenerationCurrent {
		t.Fatal("generation load returned aliased or incorrect state")
	}
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("generation-secret"), []byte("generation-metadata")); err != nil {
		t.Fatalf("idempotent InstallInitialGeneration: %v", err)
	}
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("different-generation"), []byte("generation-metadata")); !errors.Is(err, tssrun.ErrGenerationConflict) {
		t.Fatalf("conflicting InstallInitialGeneration got %v, want ErrGenerationConflict", err)
	}

	signSession := lifecycleSessionID(t, "lease-sign")
	signLease, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, signSession)
	if err != nil {
		t.Fatalf("AcquireRunLease sign: %v", err)
	}
	repeated, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, signSession)
	if err != nil || repeated.Token != signLease.Token {
		t.Fatalf("idempotent lease got token=%d err=%v, want token=%d", repeated.Token, err, signLease.Token)
	}
	presignLease, err := store.AcquireRunLease(ctx, binding, tssrun.RunPresign, lifecycleSessionID(t, "lease-presign"))
	if err != nil {
		t.Fatalf("AcquireRunLease presign: %v", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunRefresh, lifecycleSessionID(t, "lease-refresh-blocked")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("refresh alongside shared leases got %v, want ErrRunLeaseConflict", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunChildDerivation, signSession); !errors.Is(err, tssrun.ErrSessionAlreadyUsed) {
		t.Fatalf("same session different kind got %v, want ErrSessionAlreadyUsed", err)
	}
	if err := store.FinishRunLease(ctx, signLease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease sign: %v", err)
	}
	if err := store.FinishRunLease(ctx, presignLease, tssrun.LeaseAborted); err != nil {
		t.Fatalf("FinishRunLease presign: %v", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, signSession); !errors.Is(err, tssrun.ErrSessionAlreadyUsed) {
		t.Fatalf("terminal session reuse got %v, want ErrSessionAlreadyUsed", err)
	}

	refreshLease, err := store.AcquireRunLease(ctx, binding, tssrun.RunRefresh, lifecycleSessionID(t, "lease-refresh"))
	if err != nil {
		t.Fatalf("AcquireRunLease refresh: %v", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, lifecycleSessionID(t, "lease-sign-blocked")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("sign alongside refresh got %v, want ErrRunLeaseConflict", err)
	}
	if err := store.FinishRunLease(ctx, refreshLease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease refresh: %v", err)
	}

	stale := generationBinding(binding.KeyID, "gen-stale", "epoch-stale")
	if _, err := store.AcquireRunLease(ctx, stale, tssrun.RunSign, lifecycleSessionID(t, "lease-stale")); !errors.Is(err, tssrun.ErrGenerationNotCurrent) {
		t.Fatalf("stale generation lease got %v, want ErrGenerationNotCurrent", err)
	}
}

func testAttemptAtomicityAndUnknownOutcome(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	presignLease := commitConformanceAvailablePresign(t, store, binding, "presign-1", []byte("presign-secret"), []byte("presign-metadata"), "atomicity")
	if err := store.CommitAvailablePresignFromLease(ctx, presignLease, "presign-1", []byte("presign-secret"), []byte("presign-metadata")); err != nil {
		t.Fatalf("idempotent CommitAvailablePresignFromLease: %v", err)
	}
	conflictingLease, err := store.AcquireRunLease(ctx, binding, tssrun.RunPresign, lifecycleSessionID(t, "atomicity-conflicting-presign"))
	if err != nil {
		t.Fatalf("AcquireRunLease conflicting presign: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(ctx, conflictingLease, "presign-1", []byte("different-presign"), []byte("presign-metadata")); !errors.Is(err, tssrun.ErrPresignUnavailable) {
		t.Fatalf("conflicting CommitAvailablePresignFromLease got %v, want ErrPresignUnavailable", err)
	}
	candidate, err := store.PreparePresignCandidate(ctx, binding, "presign-1")
	if err != nil {
		t.Fatalf("PreparePresignCandidate: %v", err)
	}
	candidate.Blob[0] ^= 0xff
	reloaded, err := store.PreparePresignCandidate(ctx, binding, "presign-1")
	if err != nil || string(reloaded.Blob) != "presign-secret" {
		t.Fatalf("read-only prepare mutated stored presign: blob=%q err=%v", reloaded.Blob, err)
	}

	sessionID := lifecycleSessionID(t, "attempt-session")
	intent := lifecycleAttemptIntent("attempt-1", sessionID, "intent-1")
	if _, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox")); !errors.Is(err, tssrun.ErrRunLeaseNotFound) {
		t.Fatalf("commit without sign lease got %v, want ErrRunLeaseNotFound", err)
	}
	if _, err := store.PreparePresignCandidate(ctx, binding, "presign-1"); err != nil {
		t.Fatalf("failed precondition consumed presign: %v", err)
	}
	lease, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, sessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	commit, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
	if err != nil || commit.Status != tssrun.AttemptCreated {
		t.Fatalf("CommitSignAttempt status=%v err=%v, want AttemptCreated", commit.Status, err)
	}
	retry, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
	if err != nil || retry.Status != tssrun.AttemptExistingSame || !bytes.Equal(retry.Record.OutboxDigest, commit.Record.OutboxDigest) {
		t.Fatalf("exact retry status=%v err=%v", retry.Status, err)
	}
	if _, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("different-outbox")); !errors.Is(err, tssrun.ErrAttemptNonDeterminism) {
		t.Fatalf("different exact outbox got %v, want ErrAttemptNonDeterminism", err)
	}
	differentAttempt := intent.Clone()
	differentAttempt.AttemptID = "attempt-2"
	if _, err := store.CommitSignAttempt(ctx, binding, "presign-1", differentAttempt, []byte("exact-outbox")); !errors.Is(err, tssrun.ErrAttemptNonDeterminism) {
		t.Fatalf("same intent different attempt got %v, want ErrAttemptNonDeterminism", err)
	}
	differentIntent := lifecycleAttemptIntent("attempt-3", sessionID, "other-intent")
	if _, err := store.CommitSignAttempt(ctx, binding, "presign-1", differentIntent, []byte("exact-outbox")); !errors.Is(err, tssrun.ErrAttemptConflict) {
		t.Fatalf("different intent got %v, want ErrAttemptConflict", err)
	}
	if _, err := store.PreparePresignCandidate(ctx, binding, "presign-1"); !errors.Is(err, tssrun.ErrPresignUnavailable) {
		t.Fatalf("claimed presign prepare got %v, want ErrPresignUnavailable", err)
	}

	// Model a database commit that succeeded but whose response was lost. The
	// only safe recovery path is the exact query carried by the outcome-unknown
	// error; no second claim or new intent is attempted.
	storeFailure := errors.New("database response lost")
	unknown := &tssrun.AttemptOutcomeUnknownError{Cause: storeFailure, Query: commit.Record.Query()}
	if !errors.Is(unknown, tssrun.ErrAttemptOutcomeUnknown) || !errors.Is(unknown, storeFailure) {
		t.Fatalf("outcome-unknown error did not preserve categories: %v", unknown)
	}
	recovered, err := store.QueryAttemptOutcome(ctx, unknown.Query)
	if err != nil || recovered.Intent.AttemptID != intent.AttemptID || !bytes.Equal(recovered.ExactOutbox, []byte("exact-outbox")) {
		t.Fatalf("QueryAttemptOutcome recovered=%v err=%v", recovered.Intent.AttemptID, err)
	}
	wrongQuery := unknown.Query.Clone()
	wrongQuery.IntentDigest = runDigest("wrong-intent")
	if _, err := store.QueryAttemptOutcome(ctx, wrongQuery); !errors.Is(err, tssrun.ErrAttemptConflict) {
		t.Fatalf("wrong recovery query got %v, want ErrAttemptConflict", err)
	}
	if err := store.FinishRunLease(ctx, lease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease: %v", err)
	}
}

func testConcurrentPresignClaim(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	commitConformanceAvailablePresign(t, store, binding, "presign-1", []byte("presign"), []byte("public-metadata"), "concurrent-claim")
	type claimContender struct {
		intent tssrun.SignAttemptIntent
		err    error
		commit tssrun.AttemptCommit
	}
	contenders := []*claimContender{
		{intent: lifecycleAttemptIntent("attempt-1", lifecycleSessionID(t, "concurrent-1"), "intent-1")},
		{intent: lifecycleAttemptIntent("attempt-2", lifecycleSessionID(t, "concurrent-2"), "intent-2")},
	}
	for _, contender := range contenders {
		if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, contender.intent.SessionID); err != nil {
			t.Fatalf("AcquireRunLease: %v", err)
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, contender := range contenders {
		wg.Add(1)
		go func(c *claimContender) {
			defer wg.Done()
			<-start
			c.commit, c.err = store.CommitSignAttempt(ctx, binding, "presign-1", c.intent, []byte("exact-"+c.intent.AttemptID))
		}(contender)
	}
	close(start)
	wg.Wait()

	var winners, conflicts int
	for _, contender := range contenders {
		switch {
		case contender.err == nil && contender.commit.Status == tssrun.AttemptCreated:
			winners++
			if _, err := store.QueryAttemptOutcome(ctx, contender.commit.Record.Query()); err != nil {
				t.Fatalf("winner query: %v", err)
			}
		case errors.Is(contender.err, tssrun.ErrAttemptConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent claim status=%v err=%v", contender.commit.Status, contender.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("concurrent claims winners=%d conflicts=%d, want one each", winners, conflicts)
	}
}

func testConcurrentExactAttemptRetry(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	commitConformanceAvailablePresign(t, store, binding, "presign-1", []byte("presign"), []byte("public-metadata"), "concurrent-exact-retry")
	intent := lifecycleAttemptIntent("attempt-1", lifecycleSessionID(t, "same-attempt"), "same-intent")
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, intent.SessionID); err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	start := make(chan struct{})
	statuses := make(chan tssrun.AttemptCommitStatus, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			<-start
			commit, err := store.CommitSignAttempt(ctx, binding, "presign-1", intent, []byte("exact-outbox"))
			statuses <- commit.Status
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(statuses)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("exact concurrent retry: %v", err)
		}
	}
	counts := map[tssrun.AttemptCommitStatus]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[tssrun.AttemptCreated] != 1 || counts[tssrun.AttemptExistingSame] != 1 {
		t.Fatalf("commit statuses=%v, want one created and one existing", counts)
	}
}

func testAttemptProgressAndCutover(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	commitConformanceAvailablePresign(t, store, binding, "presign-claimed", []byte("presign-claimed-secret"), []byte("public-metadata"), "cutover-claimed")
	commitConformanceAvailablePresign(t, store, binding, "presign-old-available", []byte("presign-old-secret"), []byte("public-metadata-old-available"), "cutover-available")
	intent := lifecycleAttemptIntent("attempt-1", lifecycleSessionID(t, "cutover-attempt"), "intent")
	lease, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, intent.SessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	commit, err := store.CommitSignAttempt(ctx, binding, "presign-claimed", intent, []byte("exact-outbox"))
	if err != nil {
		t.Fatalf("CommitSignAttempt: %v", err)
	}
	target := generationBinding(binding.KeyID, "gen-2", "epoch-2")
	if _, err := store.BeginCutover(ctx, binding, target); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("cutover with active sign lease got %v, want ErrRunLeaseConflict", err)
	}
	if err := store.FinishRunLease(ctx, lease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease: %v", err)
	}
	if _, err := store.BeginCutover(ctx, binding, target); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("cutover with pending attempt got %v, want ErrRunLeaseConflict", err)
	}
	query := commit.Record.Query()
	completed, err := store.CompleteAttempt(ctx, query, []byte("completion"))
	if err != nil {
		t.Fatalf("CompleteAttempt: %v", err)
	}
	if completed.Terminal() {
		t.Fatal("completion without delivery became terminal")
	}
	if _, err := store.BeginCutover(ctx, binding, target); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("cutover with undelivered completion got %v, want ErrRunLeaseConflict", err)
	}
	delivered, err := store.MarkAttemptDelivered(ctx, query, []byte("delivery"))
	if err != nil {
		t.Fatalf("MarkAttemptDelivered: %v", err)
	}
	if !delivered.Terminal() || len(delivered.ExactOutbox) != 0 || len(delivered.PresignMetadata) == 0 {
		t.Fatal("terminal attempt lost public metadata or retained exact outbox")
	}
	if repeated, err := store.MarkAttemptDelivered(ctx, query, []byte("delivery")); err != nil || !repeated.Terminal() {
		t.Fatalf("idempotent delivery terminal=%v err=%v", repeated.Terminal(), err)
	}
	if _, err := store.MarkAttemptDelivered(ctx, query, []byte("other-delivery")); !errors.Is(err, tssrun.ErrAttemptConflict) {
		t.Fatalf("conflicting delivery got %v, want ErrAttemptConflict", err)
	}

	fence, err := store.BeginCutover(ctx, binding, target)
	if err != nil {
		t.Fatalf("BeginCutover: %v", err)
	}
	repeatedFence, err := store.BeginCutover(ctx, binding, target)
	if err != nil || repeatedFence.Token != fence.Token {
		t.Fatalf("idempotent BeginCutover token=%d err=%v, want %d", repeatedFence.Token, err, fence.Token)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunChildDerivation, lifecycleSessionID(t, "fenced-derive")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("fenced generation lease got %v, want ErrRunLeaseConflict", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunPresign, lifecycleSessionID(t, "fenced-presign")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("fenced generation presign lease got %v, want ErrRunLeaseConflict", err)
	}
	targetRecord, err := store.CommitCutover(ctx, fence, []byte("target-generation-secret"), []byte("target-metadata"))
	if err != nil {
		t.Fatalf("CommitCutover: %v", err)
	}
	if targetRecord.Binding != target || targetRecord.Status != tssrun.GenerationCurrent {
		t.Fatal("CommitCutover returned wrong target generation")
	}
	if _, err := store.CommitCutover(ctx, fence, []byte("target-generation-secret"), []byte("target-metadata")); err != nil {
		t.Fatalf("idempotent CommitCutover: %v", err)
	}
	if _, err := store.CommitCutover(ctx, fence, []byte("different-target"), []byte("target-metadata")); !errors.Is(err, tssrun.ErrCutoverConflict) {
		t.Fatalf("conflicting CommitCutover got %v, want ErrCutoverConflict", err)
	}
	current, err := store.LoadCurrentGeneration(ctx, binding.KeyID)
	if err != nil || current.Binding != target || string(current.Blob) != "target-generation-secret" {
		t.Fatalf("current after cutover binding=%v blob=%q err=%v", current.Binding, current.Blob, err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, lifecycleSessionID(t, "retired-sign")); !errors.Is(err, tssrun.ErrGenerationNotCurrent) {
		t.Fatalf("retired generation lease got %v, want ErrGenerationNotCurrent", err)
	}
	if err := store.BurnPresign(ctx, binding, "presign-old-available", "operator burn"); !errors.Is(err, tssrun.ErrPresignBurned) {
		t.Fatalf("old epoch presign after cutover got %v, want ErrPresignBurned", err)
	}
	targetLease, err := store.AcquireRunLease(ctx, target, tssrun.RunChildDerivation, lifecycleSessionID(t, "target-derive"))
	if err != nil {
		t.Fatalf("target generation lease: %v", err)
	}
	if err := store.FinishRunLease(ctx, targetLease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("FinishRunLease target: %v", err)
	}
}

func testAbortAndBurn(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	commitConformanceAvailablePresign(t, store, binding, "presign-burn", []byte("burn-secret"), []byte("public-metadata"), "burn")
	if err := store.BurnPresign(ctx, binding, "presign-burn", "operator discard"); err != nil {
		t.Fatalf("BurnPresign: %v", err)
	}
	if err := store.BurnPresign(ctx, binding, "presign-burn", "operator discard"); err != nil {
		t.Fatalf("idempotent BurnPresign: %v", err)
	}
	if _, err := store.PreparePresignCandidate(ctx, binding, "presign-burn"); !errors.Is(err, tssrun.ErrPresignBurned) {
		t.Fatalf("burned prepare got %v, want ErrPresignBurned", err)
	}

	commitConformanceAvailablePresign(t, store, binding, "presign-abort", []byte("abort-secret"), []byte("public-metadata-abort"), "abort")
	intent := lifecycleAttemptIntent("attempt-abort", lifecycleSessionID(t, "attempt-abort"), "abort-intent")
	lease, err := store.AcquireRunLease(ctx, binding, tssrun.RunSign, intent.SessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	commit, err := store.CommitSignAttempt(ctx, binding, "presign-abort", intent, []byte("abort-outbox"))
	if err != nil {
		t.Fatalf("CommitSignAttempt: %v", err)
	}
	query := commit.Record.Query()
	aborted, err := store.AbortAttempt(ctx, query, "protocol abort")
	if err != nil {
		t.Fatalf("AbortAttempt: %v", err)
	}
	if !aborted.Terminal() || len(aborted.PresignMetadata) == 0 || len(aborted.ExactOutbox) != 0 {
		t.Fatal("aborted attempt is non-terminal or retained recovery secrets")
	}
	if _, err := store.AbortAttempt(ctx, query, "protocol abort"); err != nil {
		t.Fatalf("idempotent AbortAttempt: %v", err)
	}
	if _, err := store.AbortAttempt(ctx, query, "other abort"); !errors.Is(err, tssrun.ErrAttemptConflict) {
		t.Fatalf("conflicting abort got %v, want ErrAttemptConflict", err)
	}
	if _, err := store.CompleteAttempt(ctx, query, []byte("completion")); !errors.Is(err, tssrun.ErrAttemptConflict) {
		t.Fatalf("complete aborted attempt got %v, want ErrAttemptConflict", err)
	}
	if err := store.FinishRunLease(ctx, lease, tssrun.LeaseAborted); err != nil {
		t.Fatalf("FinishRunLease: %v", err)
	}
}

func testConcurrentLeaseAndCutoverFence(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, source := lifecycleStoreWithGeneration(t, newStore)
	target := generationBinding(source.KeyID, "gen-2", "epoch-2")
	sessionID := lifecycleSessionID(t, "lease-cutover-race")
	start := make(chan struct{})
	var lease tssrun.RunLease
	var fence tssrun.CutoverFence
	var leaseErr, fenceErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		lease, leaseErr = store.AcquireRunLease(ctx, source, tssrun.RunSign, sessionID)
	}()
	go func() {
		defer wg.Done()
		<-start
		fence, fenceErr = store.BeginCutover(ctx, source, target)
	}()
	close(start)
	wg.Wait()

	switch {
	case leaseErr == nil && errors.Is(fenceErr, tssrun.ErrRunLeaseConflict):
		if err := store.FinishRunLease(ctx, lease, tssrun.LeaseAborted); err != nil {
			t.Fatalf("FinishRunLease race winner: %v", err)
		}
	case fenceErr == nil && errors.Is(leaseErr, tssrun.ErrRunLeaseConflict):
		if err := store.AbortCutover(ctx, fence, "race test cleanup"); err != nil {
			t.Fatalf("AbortCutover race winner: %v", err)
		}
	default:
		t.Fatalf("lease/cutover race leaseErr=%v fenceErr=%v, want exactly one winner", leaseErr, fenceErr)
	}
}

func testConcurrentAttemptAndCutoverFence(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, source := lifecycleStoreWithGeneration(t, newStore)
	target := generationBinding(source.KeyID, "gen-2", "epoch-2")
	commitConformanceAvailablePresign(t, store, source, "race-presign", []byte("presign-secret"), []byte("public-metadata"), "attempt-cutover-race")
	sessionID := lifecycleSessionID(t, "attempt-cutover-race")
	lease, err := store.AcquireRunLease(ctx, source, tssrun.RunSign, sessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	intent := lifecycleAttemptIntent("race-attempt", sessionID, "race-intent")
	query := tssrun.AttemptQuery{
		Binding: source, PresignID: "race-presign", AttemptID: intent.AttemptID, IntentDigest: bytes.Clone(intent.IntentDigest),
	}

	start := make(chan struct{})
	var commit tssrun.AttemptCommit
	var fence tssrun.CutoverFence
	var commitErr, finishErr, fenceErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		commit, commitErr = store.CommitSignAttempt(ctx, source, "race-presign", intent, []byte("race-outbox"))
	}()
	go func() {
		defer wg.Done()
		<-start
		finishErr = store.FinishRunLease(ctx, lease, tssrun.LeaseCompleted)
		if finishErr == nil {
			fence, fenceErr = store.BeginCutover(ctx, source, target)
		}
	}()
	close(start)
	wg.Wait()
	if finishErr != nil {
		t.Fatalf("FinishRunLease race: %v", finishErr)
	}

	switch {
	case commitErr == nil && errors.Is(fenceErr, tssrun.ErrRunLeaseConflict):
		recovered, err := store.QueryAttemptOutcome(ctx, commit.Record.Query())
		if err != nil || string(recovered.ExactOutbox) != "race-outbox" {
			t.Fatalf("attempt winner recovery outbox=%q err=%v", recovered.ExactOutbox, err)
		}
		if _, err := store.AbortAttempt(ctx, commit.Record.Query(), "race cleanup"); err != nil {
			t.Fatalf("AbortAttempt race cleanup: %v", err)
		}
	case fenceErr == nil && (errors.Is(commitErr, tssrun.ErrRunLeaseNotFound) || errors.Is(commitErr, tssrun.ErrRunLeaseConflict)):
		if _, err := store.QueryAttemptOutcome(ctx, query); !errors.Is(err, tssrun.ErrAttemptNotFound) {
			t.Fatalf("fence winner left attempt outcome: %v", err)
		}
		if err := store.AbortCutover(ctx, fence, "race cleanup"); err != nil {
			t.Fatalf("AbortCutover race cleanup: %v", err)
		}
		if _, err := store.PreparePresignCandidate(ctx, source, "race-presign"); err != nil {
			t.Fatalf("fence winner consumed presign: %v", err)
		}
	default:
		t.Fatalf("attempt/cutover race commitErr=%v finishErr=%v fenceErr=%v, want exactly one durable winner", commitErr, finishErr, fenceErr)
	}
}

func testLeaseCommittedPresign(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	lease, err := store.AcquireRunLease(ctx, binding, tssrun.RunPresign, lifecycleSessionID(t, "lease-presign-commit"))
	if err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(ctx, lease, "presign-1", []byte("presign-secret"), []byte("public-metadata")); err != nil {
		t.Fatalf("CommitAvailablePresignFromLease: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(ctx, lease, "presign-1", []byte("presign-secret"), []byte("public-metadata")); err != nil {
		t.Fatalf("idempotent CommitAvailablePresignFromLease: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(ctx, lease, "presign-1", []byte("different-secret"), []byte("public-metadata")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("conflicting lease commit got %v, want ErrRunLeaseConflict", err)
	}
	candidate, err := store.PreparePresignCandidate(ctx, binding, "presign-1")
	if err != nil || string(candidate.Blob) != "presign-secret" {
		t.Fatalf("PreparePresignCandidate blob=%q err=%v", candidate.Blob, err)
	}
	if err := store.FinishRunLease(ctx, lease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("completed lease retry: %v", err)
	}

	duplicateLease, err := store.AcquireRunLease(ctx, binding, tssrun.RunPresign, lifecycleSessionID(t, "lease-presign-duplicate-artifact"))
	if err != nil {
		t.Fatalf("AcquireRunLease duplicate artifact: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(ctx, duplicateLease, "presign-2", []byte("other-secret"), []byte("public-metadata")); !errors.Is(err, tssrun.ErrPresignUnavailable) {
		t.Fatalf("duplicate public artifact got %v, want ErrPresignUnavailable", err)
	}
	if err := store.FinishRunLease(ctx, duplicateLease, tssrun.LeaseAborted); err != nil {
		t.Fatalf("abort duplicate artifact lease: %v", err)
	}
}

func testRefreshFailureMarker(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, binding := lifecycleStoreWithGeneration(t, newStore)
	lease, err := store.AcquireRunLease(ctx, binding, tssrun.RunRefresh, lifecycleSessionID(t, "failed-refresh"))
	if err != nil {
		t.Fatalf("AcquireRunLease refresh: %v", err)
	}
	record, err := store.MarkProtocolRefreshFailed(ctx, lease, "protocol verification failed")
	if err != nil || record.KeyID != binding.KeyID || record.SessionID != lease.SessionID {
		t.Fatalf("MarkProtocolRefreshFailed record=%v err=%v", record, err)
	}
	if repeated, err := store.MarkProtocolRefreshFailed(ctx, lease, "protocol verification failed"); err != nil || repeated != record {
		t.Fatalf("idempotent MarkProtocolRefreshFailed record=%v err=%v", repeated, err)
	}
	if _, err := store.MarkProtocolRefreshFailed(ctx, lease, "different failure"); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("conflicting refresh marker got %v, want ErrRunLeaseConflict", err)
	}
	if _, err := store.AcquireRunLease(ctx, binding, tssrun.RunRefresh, lifecycleSessionID(t, "later-refresh")); !errors.Is(err, tssrun.ErrRefreshDisabled) {
		t.Fatalf("later refresh got %v, want ErrRefreshDisabled", err)
	}
	for _, kind := range []tssrun.RunKind{tssrun.RunSign, tssrun.RunPresign} {
		allowed, err := store.AcquireRunLease(ctx, binding, kind, lifecycleSessionID(t, "allowed-"+string(kind)))
		if err != nil {
			t.Fatalf("AcquireRunLease %s after refresh failure: %v", kind, err)
		}
		if err := store.FinishRunLease(ctx, allowed, tssrun.LeaseAborted); err != nil {
			t.Fatalf("FinishRunLease %s: %v", kind, err)
		}
	}
}

func testCutoverFromLease(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()

	childStore, childSource := lifecycleStoreWithGeneration(t, newStore)
	childLease, err := childStore.AcquireRunLease(ctx, childSource, tssrun.RunChildDerivation, lifecycleSessionID(t, "child-not-cutover"))
	if err != nil {
		t.Fatalf("AcquireRunLease child: %v", err)
	}
	childTarget := generationBinding(childSource.KeyID, "gen-2", "epoch-2")
	if _, err := childStore.BeginCutoverFromLease(ctx, childLease, childTarget); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("child cutover got %v, want ErrInvalidLifecycleRecord", err)
	}
	if err := childStore.FinishRunLease(ctx, childLease, tssrun.LeaseAborted); err != nil {
		t.Fatalf("FinishRunLease rejected child: %v", err)
	}

	store, source := lifecycleStoreWithGeneration(t, newStore)
	lease, err := store.AcquireRunLease(ctx, source, tssrun.RunRefresh, lifecycleSessionID(t, "cutover-from-refresh"))
	if err != nil {
		t.Fatalf("AcquireRunLease refresh: %v", err)
	}
	targets := []tssrun.GenerationBinding{
		generationBinding(source.KeyID, "gen-2", "epoch-2"),
		generationBinding(source.KeyID, "gen-3", "epoch-3"),
	}
	type outcome struct {
		fence tssrun.CutoverFence
		err   error
	}
	outcomes := make([]outcome, len(targets))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			outcomes[index].fence, outcomes[index].err = store.BeginCutoverFromLease(ctx, lease, targets[index])
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, outcome := range outcomes {
		switch {
		case outcome.err == nil:
			if winner != -1 {
				t.Fatal("two cutover targets won one lease")
			}
			winner = i
		case errors.Is(outcome.err, tssrun.ErrRunLeaseConflict):
		default:
			t.Fatalf("cutover contender %d: %v", i, outcome.err)
		}
	}
	if winner == -1 {
		t.Fatal("no cutover target won")
	}
	winnerFence := outcomes[winner].fence
	if repeated, err := store.BeginCutoverFromLease(ctx, lease, targets[winner]); err != nil || repeated != winnerFence {
		t.Fatalf("idempotent BeginCutoverFromLease fence=%v err=%v", repeated, err)
	}
	if _, err := store.CommitCutover(ctx, winnerFence, []byte("target-secret"), []byte("target-metadata")); err != nil {
		t.Fatalf("CommitCutover: %v", err)
	}
	current, err := store.LoadCurrentGeneration(ctx, source.KeyID)
	if err != nil || current.Binding != targets[winner] {
		t.Fatalf("current binding=%v err=%v, want %v", current.Binding, err, targets[winner])
	}

	reshareStore, reshareSource := lifecycleStoreWithGeneration(t, newStore)
	reshareLease, err := reshareStore.AcquireRunLease(ctx, reshareSource, tssrun.RunReshare, lifecycleSessionID(t, "cutover-from-reshare"))
	if err != nil {
		t.Fatalf("AcquireRunLease reshare: %v", err)
	}
	reshareTarget := generationBinding(reshareSource.KeyID, "gen-reshared", "epoch-reshared")
	fence, err := reshareStore.BeginCutoverFromLease(ctx, reshareLease, reshareTarget)
	if err != nil {
		t.Fatalf("BeginCutoverFromLease reshare: %v", err)
	}
	if err := reshareStore.AbortCutover(ctx, fence, "conformance cleanup"); err != nil {
		t.Fatalf("AbortCutover reshare: %v", err)
	}
}

func testChildGenerationFromLease(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store, parent := lifecycleStoreWithGeneration(t, newStore)
	lease, err := store.AcquireRunLease(ctx, parent, tssrun.RunChildDerivation, lifecycleSessionID(t, "child-generation"))
	if err != nil {
		t.Fatalf("AcquireRunLease child: %v", err)
	}
	if _, err := store.CommitInitialGenerationFromLease(ctx, lease, parent, []byte("child-secret"), []byte("child-metadata")); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("same-key child got %v, want ErrInvalidLifecycleRecord", err)
	}
	reusedEpoch := generationBinding("child-key", "child-gen-1", "child-epoch-1")
	reusedEpoch.EpochID = parent.EpochID
	if _, err := store.CommitInitialGenerationFromLease(ctx, lease, reusedEpoch, []byte("child-secret"), []byte("child-metadata")); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("child with parent epoch got %v, want ErrInvalidLifecycleRecord", err)
	}
	child := generationBinding("child-key", "child-gen-1", "child-epoch-1")
	record, err := store.CommitInitialGenerationFromLease(ctx, lease, child, []byte("child-secret"), []byte("child-metadata"))
	if err != nil || record.Binding != child {
		t.Fatalf("CommitInitialGenerationFromLease record=%v err=%v", record.Binding, err)
	}
	if repeated, err := store.CommitInitialGenerationFromLease(ctx, lease, child, []byte("child-secret"), []byte("child-metadata")); err != nil || repeated.Binding != child {
		t.Fatalf("idempotent child commit record=%v err=%v", repeated.Binding, err)
	}
	if _, err := store.CommitInitialGenerationFromLease(ctx, lease, child, []byte("different-secret"), []byte("child-metadata")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("conflicting child commit got %v, want ErrRunLeaseConflict", err)
	}
	loadedChild, err := store.LoadCurrentGeneration(ctx, child.KeyID)
	if err != nil || loadedChild.Binding != child || string(loadedChild.Blob) != "child-secret" {
		t.Fatalf("LoadCurrentGeneration child binding=%v blob=%q err=%v", loadedChild.Binding, loadedChild.Blob, err)
	}
	loadedParent, err := store.LoadCurrentGeneration(ctx, parent.KeyID)
	if err != nil || loadedParent.Binding != parent || string(loadedParent.Blob) != "generation-secret" {
		t.Fatalf("parent changed binding=%v blob=%q err=%v", loadedParent.Binding, loadedParent.Blob, err)
	}
	if err := store.FinishRunLease(ctx, lease, tssrun.LeaseCompleted); err != nil {
		t.Fatalf("completed child lease retry: %v", err)
	}
}

func testReshareReceiverGeneration(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store := newStore(t)
	source := generationBinding("receiver-key", "source-gen", "source-epoch")
	target := generationBinding(source.KeyID, "target-gen", "target-epoch")
	anchor := tssrun.ReshareReceiverAnchor{
		Source:              source,
		TargetKeyGeneration: target.KeyGeneration,
		SessionID:           lifecycleSessionID(t, "receiver-join"),
		PlanDigest:          runDigest("receiver-plan"),
		SourceEpochDigest:   runDigest("receiver-source-epoch"),
	}
	lease, err := store.AcquireReshareReceiverLease(ctx, anchor)
	if err != nil {
		t.Fatalf("AcquireReshareReceiverLease: %v", err)
	}
	anchor.PlanDigest[0] ^= 0xff
	anchor.PlanDigest = runDigest("receiver-plan")
	repeated, err := store.AcquireReshareReceiverLease(ctx, anchor)
	if err != nil || repeated.Token != lease.Token {
		t.Fatalf("idempotent receiver lease token=%d err=%v, want token=%d", repeated.Token, err, lease.Token)
	}
	if _, err := store.LoadCurrentGeneration(ctx, source.KeyID); !errors.Is(err, tssrun.ErrGenerationNotCurrent) {
		t.Fatalf("receiver anchor became current: %v", err)
	}
	if _, err := store.AcquireRunLease(ctx, source, tssrun.RunReshare, anchor.SessionID); !errors.Is(err, tssrun.ErrSessionAlreadyUsed) {
		t.Fatalf("normal lease reused receiver session: %v", err)
	}
	if err := store.FinishRunLease(ctx, lease, tssrun.LeaseCompleted); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("non-atomic receiver completion got %v, want ErrRunLeaseConflict", err)
	}
	wrongTarget := generationBinding(source.KeyID, "wrong-target", "wrong-target-epoch")
	if _, err := store.CommitInitialGenerationFromReshareLease(ctx, lease, wrongTarget, []byte("receiver-secret"), nil); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("undeclared receiver target got %v, want ErrRunLeaseConflict", err)
	}
	record, err := store.CommitInitialGenerationFromReshareLease(ctx, lease, target, []byte("receiver-secret"), []byte("receiver-metadata"))
	if err != nil || record.Binding != target {
		t.Fatalf("CommitInitialGenerationFromReshareLease record=%v err=%v", record.Binding, err)
	}
	if repeated, err := store.CommitInitialGenerationFromReshareLease(ctx, lease, target, []byte("receiver-secret"), []byte("receiver-metadata")); err != nil || repeated.Binding != target {
		t.Fatalf("idempotent receiver commit record=%v err=%v", repeated.Binding, err)
	}
	if _, err := store.CommitInitialGenerationFromReshareLease(ctx, lease, target, []byte("different-secret"), []byte("receiver-metadata")); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("conflicting receiver commit got %v, want ErrRunLeaseConflict", err)
	}
	current, err := store.LoadCurrentGeneration(ctx, source.KeyID)
	if err != nil || current.Binding != target || string(current.Blob) != "receiver-secret" {
		t.Fatalf("receiver target current=%v blob=%q err=%v", current.Binding, current.Blob, err)
	}

	abortStore := newStore(t)
	abortAnchor := anchor.Clone()
	abortAnchor.SessionID = lifecycleSessionID(t, "receiver-abort")
	abortLease, err := abortStore.AcquireReshareReceiverLease(ctx, abortAnchor)
	if err != nil {
		t.Fatalf("AcquireReshareReceiverLease abort case: %v", err)
	}
	if err := abortStore.FinishRunLease(ctx, abortLease, tssrun.LeaseAborted); err != nil {
		t.Fatalf("FinishRunLease receiver abort: %v", err)
	}
	retryAnchor := abortAnchor.Clone()
	retryAnchor.SessionID = lifecycleSessionID(t, "receiver-after-abort")
	if _, err := abortStore.AcquireReshareReceiverLease(ctx, retryAnchor); err != nil {
		t.Fatalf("receiver target remained anchored after abort: %v", err)
	}
}

func testReshareRetirementAndRejoin(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) {
	ctx := context.Background()
	store := newStore(t)
	source := generationBinding("rejoining-key", "gen-1", "epoch-1")
	if _, err := store.InstallInitialGeneration(ctx, source, []byte("source-secret"), []byte("source-metadata")); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	commitConformanceAvailablePresign(t, store, source, "retired-presign", []byte("presign-secret"), []byte("presign-metadata"), "retirement")
	lease, err := store.AcquireRunLease(ctx, source, tssrun.RunReshare, lifecycleSessionID(t, "old-only-retirement"))
	if err != nil {
		t.Fatalf("AcquireRunLease reshare: %v", err)
	}
	remoteTarget := generationBinding(source.KeyID, "gen-2", "epoch-2")
	if err := store.CommitRetirementFromLease(ctx, lease, remoteTarget); err != nil {
		t.Fatalf("CommitRetirementFromLease: %v", err)
	}
	if err := store.CommitRetirementFromLease(ctx, lease, remoteTarget); err != nil {
		t.Fatalf("idempotent CommitRetirementFromLease: %v", err)
	}
	conflictingTarget := generationBinding(source.KeyID, "gen-conflict", "epoch-conflict")
	if err := store.CommitRetirementFromLease(ctx, lease, conflictingTarget); !errors.Is(err, tssrun.ErrRunLeaseConflict) {
		t.Fatalf("conflicting retirement got %v, want ErrRunLeaseConflict", err)
	}
	if _, err := store.LoadCurrentGeneration(ctx, source.KeyID); !errors.Is(err, tssrun.ErrGenerationNotCurrent) {
		t.Fatalf("retired dealer retained current generation: %v", err)
	}
	if err := store.BurnPresign(ctx, source, "retired-presign", "verify retirement"); !errors.Is(err, tssrun.ErrPresignBurned) {
		t.Fatalf("retired source presign got %v, want ErrPresignBurned", err)
	}

	rejoinTarget := generationBinding(source.KeyID, "gen-3", "epoch-3")
	anchor := tssrun.ReshareReceiverAnchor{
		Source:              remoteTarget,
		TargetKeyGeneration: rejoinTarget.KeyGeneration,
		SessionID:           lifecycleSessionID(t, "receiver-rejoin"),
		PlanDigest:          runDigest("receiver-rejoin-plan"),
		SourceEpochDigest:   runDigest("receiver-rejoin-source-epoch"),
	}
	rejoinLease, err := store.AcquireReshareReceiverLease(ctx, anchor)
	if err != nil {
		t.Fatalf("AcquireReshareReceiverLease with retired history: %v", err)
	}
	if _, err := store.CommitInitialGenerationFromReshareLease(ctx, rejoinLease, rejoinTarget, []byte("rejoined-secret"), nil); err != nil {
		t.Fatalf("CommitInitialGenerationFromReshareLease after retired history: %v", err)
	}
	current, err := store.LoadCurrentGeneration(ctx, source.KeyID)
	if err != nil || current.Binding != rejoinTarget {
		t.Fatalf("rejoined current=%v err=%v", current.Binding, err)
	}
}

func lifecycleStoreWithGeneration(t *testing.T, newStore func(testing.TB) tssrun.LifecycleStore) (tssrun.LifecycleStore, tssrun.GenerationBinding) {
	t.Helper()
	store := newStore(t)
	binding := generationBinding("key-1", "gen-1", "epoch-1")
	if _, err := store.InstallInitialGeneration(context.Background(), binding, []byte("generation-secret"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	return store, binding
}

func lifecycleAttemptIntent(attemptID string, sessionID tss.SessionID, digestLabel string) tssrun.SignAttemptIntent {
	return tssrun.SignAttemptIntent{
		AttemptID:    attemptID,
		SessionID:    sessionID,
		IntentDigest: runDigest(digestLabel),
	}
}

func commitConformanceAvailablePresign(
	t *testing.T,
	store tssrun.LifecycleStore,
	binding tssrun.GenerationBinding,
	presignID string,
	blob, metadata []byte,
	label string,
) tssrun.RunLease {
	t.Helper()
	lease, err := store.AcquireRunLease(
		context.Background(),
		binding,
		tssrun.RunPresign,
		lifecycleSessionID(t, "available-presign-"+label),
	)
	if err != nil {
		t.Fatalf("AcquireRunLease available presign: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(context.Background(), lease, presignID, blob, metadata); err != nil {
		t.Fatalf("CommitAvailablePresignFromLease: %v", err)
	}
	return lease
}

func lifecycleSessionID(t *testing.T, label string) tss.SessionID {
	t.Helper()
	digest := sha256.Sum256([]byte(label))
	sessionID, err := tss.NewSessionID(bytes.NewReader(digest[:]))
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return sessionID
}
