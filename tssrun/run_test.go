package tssrun

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

func TestMemoryRunStoreRejectsDuplicateSessionAndDigestConflict(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	duplicate := testRunIntent(t, "run-2")
	duplicate.SessionID = run.SessionID
	if err := store.CreateRun(ctx, duplicate); !errors.Is(err, ErrSessionAlreadyUsed) {
		t.Fatalf("expected ErrSessionAlreadyUsed, got %v", err)
	}
	digest := []byte("plan-digest")
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("idempotent AcceptPlan: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, []byte("other-digest")); !errors.Is(err, ErrPlanDigestConflict) {
		t.Fatalf("expected ErrPlanDigestConflict, got %v", err)
	}
}

func TestMemoryRunStoreLookupLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, ErrRunNotAccepted) {
		t.Fatalf("expected ErrRunNotAccepted, got %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, []byte("plan-digest")); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if got, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); err != nil || got.RunID != run.RunID {
		t.Fatalf("LookupBySession got (%q, %v), want run", got.RunID, err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); err != nil {
		t.Fatalf("MarkStarted: %v", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 1, LocalRunResult{KeyID: "key-1", OutputDigest: []byte("out")}); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("expected ErrRunCompleted, got %v", err)
	}
}

func TestMemoryRunStoreCompletionIsScopedToLocalParty(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	digest := []byte("plan-digest")
	for _, party := range []tss.PartyID{1, 2} {
		if err := store.AcceptPlan(ctx, run.RunID, party, digest); err != nil {
			t.Fatalf("AcceptPlan party %d: %v", party, err)
		}
		if err := store.MarkStarted(ctx, run.RunID, party); err != nil {
			t.Fatalf("MarkStarted party %d: %v", party, err)
		}
	}
	if err := store.MarkCompleted(ctx, run.RunID, 1, LocalRunResult{OutputDigest: []byte("out-1")}); err != nil {
		t.Fatalf("MarkCompleted party 1: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); err != nil {
		t.Fatalf("LookupBySession after one local completion: %v", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("completed party restart got %v, want ErrRunCompleted", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 2, LocalRunResult{OutputDigest: []byte("out-2")}); err != nil {
		t.Fatalf("MarkCompleted party 2: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("expected ErrRunCompleted after all active local parties completed, got %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 3, digest); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("late completed-run AcceptPlan got %v, want ErrRunCompleted", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("late completed-run lookup got %v, want ErrRunCompleted", err)
	}
}

func TestMemoryRunStoreRejectsLateAcceptAfterAbort(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	digest := []byte("plan-digest")
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if err := store.AbortRun(ctx, run.RunID, 1, "operator abort"); err != nil {
		t.Fatalf("AbortRun: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, ErrRunAborted) {
		t.Fatalf("aborted lookup got %v, want ErrRunAborted", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 2, digest); !errors.Is(err, ErrRunAborted) {
		t.Fatalf("late aborted-run AcceptPlan got %v, want ErrRunAborted", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, ErrRunAborted) {
		t.Fatalf("late aborted-run lookup got %v, want ErrRunAborted", err)
	}
}

func TestRegisterStartedSessionRollsBackRegistryOnStoreFailure(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	registry := NewMemorySessionRegistry()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	err := RegisterStartedSession(ctx, store, registry, run, 1, &testSession{})
	if !errors.Is(err, ErrRunNotAccepted) {
		t.Fatalf("expected ErrRunNotAccepted, got %v", err)
	}
	key := SessionKey{Protocol: run.Protocol, SessionID: run.SessionID, Party: 1}
	if _, ok, err := registry.Lookup(ctx, key); err != nil || ok {
		t.Fatalf("registry retained failed session: ok=%v err=%v", ok, err)
	}
}

func testRunIntent(t *testing.T, runID string) RunIntent {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return RunIntent{
		RunID:     runID,
		Protocol:  tss.ProtocolFROSTEd25519,
		Kind:      RunKeygen,
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2, 3),
		Threshold: 2,
	}
}
