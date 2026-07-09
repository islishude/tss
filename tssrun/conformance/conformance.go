// Package conformance provides reusable tests for tssrun integration stores.
package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

// Harness constructs integration components for conformance testing.
type Harness struct {
	NewRunStore        func(testing.TB) tssrun.RunStore
	NewSessionRegistry func(testing.TB) tssrun.SessionRegistry
	NewUnknownStore    func(testing.TB) tssrun.UnknownEnvelopeStore
}

// RunConformance runs the reusable tssrun conformance suite.
func RunConformance(t *testing.T, h Harness) {
	t.Helper()
	if h.NewRunStore != nil {
		t.Run("RunStore", func(t *testing.T) { runRunStore(t, h.NewRunStore) })
	}
	if h.NewSessionRegistry != nil {
		t.Run("SessionRegistry", func(t *testing.T) { runSessionRegistry(t, h.NewSessionRegistry) })
	}
	if h.NewUnknownStore != nil {
		t.Run("UnknownEnvelopeStore", func(t *testing.T) { runUnknownStore(t, h.NewUnknownStore) })
	}
}

func runRunStore(t *testing.T, newStore func(testing.TB) tssrun.RunStore) {
	ctx := context.Background()
	store := newStore(t)
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	duplicateRunID := testRunIntent(t, run.RunID)
	if err := store.CreateRun(ctx, duplicateRunID); !errors.Is(err, tssrun.ErrRunConflict) {
		t.Fatalf("duplicate run id: got %v, want ErrRunConflict", err)
	}
	duplicateSession := testRunIntent(t, "run-2")
	duplicateSession.SessionID = run.SessionID
	if err := store.CreateRun(ctx, duplicateSession); !errors.Is(err, tssrun.ErrSessionAlreadyUsed) {
		t.Fatalf("duplicate session: got %v, want ErrSessionAlreadyUsed", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, tssrun.ErrRunNotAccepted) {
		t.Fatalf("unaccepted lookup: got %v, want ErrRunNotAccepted", err)
	}
	digest := []byte("plan-digest")
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("idempotent AcceptPlan: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, []byte("other-digest")); !errors.Is(err, tssrun.ErrPlanDigestConflict) {
		t.Fatalf("digest conflict: got %v, want ErrPlanDigestConflict", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); err != nil {
		t.Fatalf("accepted lookup: %v", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 2); !errors.Is(err, tssrun.ErrRunNotAccepted) {
		t.Fatalf("unaccepted start: got %v, want ErrRunNotAccepted", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); err != nil {
		t.Fatalf("MarkStarted: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 2, digest); err != nil {
		t.Fatalf("AcceptPlan second party: %v", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 2); err != nil {
		t.Fatalf("MarkStarted second party: %v", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 1, tssrun.LocalRunResult{OutputDigest: []byte("out")}); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); err != nil {
		t.Fatalf("lookup after one local completion: %v", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); !errors.Is(err, tssrun.ErrRunCompleted) {
		t.Fatalf("completed party restart: got %v, want ErrRunCompleted", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 2, tssrun.LocalRunResult{OutputDigest: []byte("out-2")}); err != nil {
		t.Fatalf("MarkCompleted second party: %v", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, tssrun.ErrRunCompleted) {
		t.Fatalf("completed lookup: got %v, want ErrRunCompleted", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 3, digest); !errors.Is(err, tssrun.ErrRunCompleted) {
		t.Fatalf("late completed-run accept: got %v, want ErrRunCompleted", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); !errors.Is(err, tssrun.ErrRunCompleted) {
		t.Fatalf("late completed-run lookup: got %v, want ErrRunCompleted", err)
	}

	aborted := testRunIntent(t, "run-aborted")
	if err := store.CreateRun(ctx, aborted); err != nil {
		t.Fatalf("CreateRun aborted: %v", err)
	}
	if err := store.AcceptPlan(ctx, aborted.RunID, 1, digest); err != nil {
		t.Fatalf("AcceptPlan aborted: %v", err)
	}
	if err := store.AbortRun(ctx, aborted.RunID, 1, "operator abort"); err != nil {
		t.Fatalf("AbortRun aborted: %v", err)
	}
	if _, err := store.LookupBySession(ctx, aborted.Protocol, aborted.SessionID); !errors.Is(err, tssrun.ErrRunAborted) {
		t.Fatalf("aborted lookup: got %v, want ErrRunAborted", err)
	}
	if err := store.AcceptPlan(ctx, aborted.RunID, 2, digest); !errors.Is(err, tssrun.ErrRunAborted) {
		t.Fatalf("late aborted-run accept: got %v, want ErrRunAborted", err)
	}
	if _, err := store.LookupBySession(ctx, aborted.Protocol, aborted.SessionID); !errors.Is(err, tssrun.ErrRunAborted) {
		t.Fatalf("late aborted-run lookup: got %v, want ErrRunAborted", err)
	}
}

func runSessionRegistry(t *testing.T, newRegistry func(testing.TB) tssrun.SessionRegistry) {
	ctx := context.Background()
	registry := newRegistry(t)
	key := testSessionKey(t)
	session := &testSession{}
	if err := registry.Put(ctx, key, session); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := registry.Put(ctx, key, &testSession{}); !errors.Is(err, tssrun.ErrSessionConflict) {
		t.Fatalf("duplicate Put: got %v, want ErrSessionConflict", err)
	}
	got, ok, err := registry.Lookup(ctx, key)
	if err != nil || !ok || got != session {
		t.Fatalf("Lookup got session=%v ok=%v err=%v", got, ok, err)
	}
	wrongParty := key
	wrongParty.Party++
	if _, ok, err := registry.Lookup(ctx, wrongParty); err != nil || ok {
		t.Fatalf("wrong-party Lookup ok=%v err=%v, want miss", ok, err)
	}
	if err := registry.Retire(ctx, key); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, ok, err := registry.Lookup(ctx, key); err != nil || ok {
		t.Fatalf("retired Lookup ok=%v err=%v, want miss", ok, err)
	}
}

func runUnknownStore(t *testing.T, newStore func(testing.TB) tssrun.UnknownEnvelopeStore) {
	ctx := context.Background()
	store := newStore(t)
	in := testInboundEnvelope(t)
	if err := store.PutUnknown(ctx, in); err != nil {
		t.Fatalf("PutUnknown: %v", err)
	}
	buffered, err := store.LoadBySession(ctx, in.Protocol(), in.SessionID())
	if err != nil {
		t.Fatalf("LoadBySession: %v", err)
	}
	if len(buffered) != 1 || buffered[0].From() != in.From() {
		t.Fatalf("buffered len=%d, want original envelope", len(buffered))
	}
	if err := store.DeleteBySession(ctx, in.Protocol(), in.SessionID()); err != nil {
		t.Fatalf("DeleteBySession: %v", err)
	}
	buffered, err = store.LoadBySession(ctx, in.Protocol(), in.SessionID())
	if err != nil {
		t.Fatalf("LoadBySession after delete: %v", err)
	}
	if len(buffered) != 0 {
		t.Fatalf("buffered len=%d after delete, want 0", len(buffered))
	}
}

type testSession struct{}

// Handle accepts an inbound envelope for the conformance stub session.
func (s *testSession) Handle(tss.InboundEnvelope) ([]tss.Envelope, error) { return nil, nil }

// Completed reports whether the conformance stub session is complete.
func (s *testSession) Completed() bool { return false }

// Destroy releases the conformance stub session.
func (s *testSession) Destroy() {}

func testRunIntent(t *testing.T, runID string) tssrun.RunIntent {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return tssrun.RunIntent{
		RunID:     runID,
		Protocol:  tss.ProtocolFROSTEd25519,
		Kind:      tssrun.RunKeygen,
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2, 3),
		Threshold: 2,
	}
}

func testSessionKey(t *testing.T) tssrun.SessionKey {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return tssrun.SessionKey{Protocol: tss.ProtocolFROSTEd25519, SessionID: sessionID, Party: 1}
}

func testInboundEnvelope(t *testing.T) tss.InboundEnvelope {
	t.Helper()
	key := testSessionKey(t)
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    key.Protocol,
		SessionID:   key.SessionID,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "test.payload",
		Payload:     []byte("payload"),
	})
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	in, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{Peer: 1, Protection: tss.ChannelConfidential})
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	return in
}
