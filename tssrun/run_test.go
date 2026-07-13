package tssrun

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

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
	digest := run.PlanDigest
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, digest); err != nil {
		t.Fatalf("idempotent AcceptPlan: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, testRunDigest("other-digest")); !errors.Is(err, ErrPlanDigestConflict) {
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
	if err := store.AcceptPlan(ctx, run.RunID, 1, run.PlanDigest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if got, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); err != nil || got.RunID != run.RunID {
		t.Fatalf("LookupBySession got (%q, %v), want run", got.RunID, err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); err != nil {
		t.Fatalf("MarkStarted: %v", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 1, testKeygenRunResult(run, "out")); err != nil {
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
	digest := run.PlanDigest
	for _, party := range tss.NewPartySet(1, 2) {
		if err := store.AcceptPlan(ctx, run.RunID, party, digest); err != nil {
			t.Fatalf("AcceptPlan party %d: %v", party, err)
		}
		if err := store.MarkStarted(ctx, run.RunID, party); err != nil {
			t.Fatalf("MarkStarted party %d: %v", party, err)
		}
	}
	result1 := testKeygenRunResult(run, "out-1")
	if err := store.MarkCompleted(ctx, run.RunID, 1, result1); err != nil {
		t.Fatalf("MarkCompleted party 1: %v", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 1, result1); err != nil {
		t.Fatalf("idempotent MarkCompleted party 1: %v", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 1, testKeygenRunResult(run, "other-out")); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("overwriting completed result got %v, want ErrRunCompleted", err)
	}
	if _, err := store.LookupBySession(ctx, run.Protocol, run.SessionID); err != nil {
		t.Fatalf("LookupBySession after one local completion: %v", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("completed party restart got %v, want ErrRunCompleted", err)
	}
	if err := store.MarkCompleted(ctx, run.RunID, 2, testKeygenRunResult(run, "out-2")); err != nil {
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
	digest := run.PlanDigest
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

func TestMemoryRunStoreRejectsUnboundLifecycleMutations(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	if err := store.AcceptPlan(ctx, run.RunID, 1, testRunDigest("other-plan")); !errors.Is(err, ErrPlanDigestConflict) {
		t.Fatalf("unbound plan digest got %v, want ErrPlanDigestConflict", err)
	}
	for name, mutate := range map[string]func() error{
		"accept": func() error { return store.AcceptPlan(ctx, run.RunID, 4, run.PlanDigest) },
		"start":  func() error { return store.MarkStarted(ctx, run.RunID, 4) },
		"complete": func() error {
			return store.MarkCompleted(ctx, run.RunID, 4, LocalRunResult{OutputDigest: testRunDigest("out")})
		},
		"abort": func() error { return store.AbortRun(ctx, run.RunID, 4, "invalid party") },
	} {
		if err := mutate(); !errors.Is(err, ErrRunPartyNotParticipant) {
			t.Errorf("%s non-participant mutation got %v, want ErrRunPartyNotParticipant", name, err)
		}
	}
}

func TestMemoryRunStoreValidatesCompletionResultBinding(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRunStore()
	run := testRunIntent(t, "run-1")
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := store.AcceptPlan(ctx, run.RunID, 1, run.PlanDigest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	if err := store.MarkStarted(ctx, run.RunID, 1); err != nil {
		t.Fatalf("MarkStarted: %v", err)
	}

	for name, result := range map[string]LocalRunResult{
		"empty output digest": {KeyID: run.KeyID},
		"wrong key id":        {KeyID: "other-key", OutputDigest: testRunDigest("out")},
		"missing generation":  {KeyID: run.KeyID, OutputDigest: testRunDigest("out")},
	} {
		if err := store.MarkCompleted(ctx, run.RunID, 1, result); !errors.Is(err, ErrInvalidRunResult) {
			t.Errorf("%s got %v, want ErrInvalidRunResult", name, err)
		}
	}
	if _, ok := store.byRunID[run.RunID].completed[1]; ok {
		t.Fatal("invalid completion result advanced durable run state")
	}
}

func TestMemoryRunStoreValidatesOutputGenerationByRunKind(t *testing.T) {
	t.Parallel()
	base := testRunIntent(t, "run-1")
	for _, tc := range []struct {
		name      string
		kind      RunKind
		input     KeyGeneration
		output    KeyGeneration
		presignID string
	}{
		{name: "keygen missing output", kind: RunKeygen},
		{name: "refresh missing output", kind: RunRefresh, input: "gen-1"},
		{name: "refresh reuses input", kind: RunRefresh, input: "gen-1", output: "gen-1"},
		{name: "reshare missing output", kind: RunReshare, input: "gen-1"},
		{name: "reshare reuses input", kind: RunReshare, input: "gen-1", output: "gen-1"},
		{name: "presign changes input", kind: RunPresign, input: "gen-1", output: "gen-2", presignID: "presign-1"},
		{name: "sign changes input", kind: RunSign, input: "gen-1", output: "gen-2", presignID: "presign-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := base.Clone()
			intent.Kind = tc.kind
			intent.KeyGeneration = tc.input
			intent.PresignID = tc.presignID
			result := LocalRunResult{
				KeyID:         intent.KeyID,
				KeyGeneration: tc.output,
				PresignID:     tc.presignID,
				OutputDigest:  testRunDigest("out"),
			}
			if err := validateLocalRunResult(intent, result); !errors.Is(err, ErrInvalidRunResult) {
				t.Fatalf("validateLocalRunResult got %v, want ErrInvalidRunResult", err)
			}
		})
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

func TestRegisterStartedSessionPreservesDispatchAcrossDurableStart(t *testing.T) {
	ctx := context.Background()
	baseStore := NewMemoryRunStore()
	registry := NewMemorySessionRegistry()
	run := testRunIntent(t, "run-1")
	if err := baseStore.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := baseStore.AcceptPlan(ctx, run.RunID, 1, run.PlanDigest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	store := &markStartedStore{
		RunStore: baseStore,
		markStarted: func(ctx context.Context, runID string, self tss.PartyID) error {
			close(entered)
			<-release
			return baseStore.MarkStarted(ctx, runID, self)
		},
	}
	session := &testSession{}
	done := make(chan error, 1)
	go func() {
		done <- RegisterStartedSession(ctx, store, registry, run, 1, session)
	}()
	<-entered

	env := testEnvelope(t, run.SessionID, 2, 1)
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	in, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{Peer: 2, Protection: tss.ChannelConfidential})
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	dispatcher := Dispatcher{Self: 1, Registry: registry}
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- dispatcher.Dispatch(ctx, in)
	}()
	select {
	case err := <-dispatchDone:
		t.Fatalf("dispatch returned before durable start: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if session.handled != 0 {
		t.Fatalf("session handled %d envelopes before durable start", session.handled)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("RegisterStartedSession: %v", err)
	}
	if err := <-dispatchDone; err != nil {
		t.Fatalf("dispatch after durable start: %v", err)
	}
	if session.handled != 1 {
		t.Fatalf("session handled %d envelopes after activation, want 1", session.handled)
	}
}

func TestRegisterStartedSessionUnblocksDispatchOnDurableStartFailure(t *testing.T) {
	ctx := context.Background()
	baseStore := NewMemoryRunStore()
	registry := NewMemorySessionRegistry()
	run := testRunIntent(t, "run-1")
	if err := baseStore.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := baseStore.AcceptPlan(ctx, run.RunID, 1, run.PlanDigest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	markErr := errors.New("durable start failed")
	store := &markStartedStore{
		RunStore: baseStore,
		markStarted: func(context.Context, string, tss.PartyID) error {
			close(entered)
			<-release
			return markErr
		},
	}
	session := &testSession{}
	registerDone := make(chan error, 1)
	go func() {
		registerDone <- RegisterStartedSession(ctx, store, registry, run, 1, session)
	}()
	<-entered

	env := testEnvelope(t, run.SessionID, 2, 1)
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	in, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{Peer: 2, Protection: tss.ChannelConfidential})
	if err != nil {
		t.Fatal(err)
	}
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- (&Dispatcher{Self: 1, Registry: registry}).Dispatch(ctx, in)
	}()
	select {
	case err := <-dispatchDone:
		t.Fatalf("dispatch returned before durable decision: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	if err := <-registerDone; !errors.Is(err, markErr) {
		t.Fatalf("RegisterStartedSession got %v, want %v", err, markErr)
	}
	if err := <-dispatchDone; !errors.Is(err, markErr) {
		t.Fatalf("dispatch got %v, want %v", err, markErr)
	}
	if session.handled != 0 {
		t.Fatalf("failed start handled %d envelopes", session.handled)
	}
	key := SessionKey{Protocol: run.Protocol, SessionID: run.SessionID, Party: 1}
	if _, ok, err := registry.Lookup(ctx, key); err != nil || ok {
		t.Fatalf("registry retained failed session: ok=%v err=%v", ok, err)
	}
}

func TestRegisterStartedSessionCleansUpWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	baseStore := NewMemoryRunStore()
	registry := NewMemorySessionRegistry()
	run := testRunIntent(t, "run-1")
	if err := baseStore.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := baseStore.AcceptPlan(ctx, run.RunID, 1, run.PlanDigest); err != nil {
		t.Fatalf("AcceptPlan: %v", err)
	}
	markErr := errors.New("durable start failed")
	store := &markStartedStore{
		RunStore: baseStore,
		markStarted: func(context.Context, string, tss.PartyID) error {
			cancel()
			return markErr
		},
	}
	if err := RegisterStartedSession(ctx, store, registry, run, 1, &testSession{}); !errors.Is(err, markErr) {
		t.Fatalf("RegisterStartedSession got %v, want durable start failure", err)
	}
	key := SessionKey{Protocol: run.Protocol, SessionID: run.SessionID, Party: 1}
	if _, ok, err := registry.Lookup(context.Background(), key); err != nil || ok {
		t.Fatalf("registry retained failed session after cancellation: ok=%v err=%v", ok, err)
	}
}

func TestMemoryRunStoreValidatesRunKindMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RunIntent)
	}{
		{name: "missing key id", mutate: func(run *RunIntent) { run.KeyID = "" }},
		{name: "refresh missing generation", mutate: func(run *RunIntent) { run.Kind = RunRefresh }},
		{name: "reshare missing generation", mutate: func(run *RunIntent) { run.Kind = RunReshare }},
		{name: "FROST presign", mutate: func(run *RunIntent) {
			run.Kind = RunPresign
			run.Signers = tss.NewPartySet(1, 2)
			run.KeyGeneration = "gen-1"
			run.PresignID = "presign-1"
			run.ContextDigest = testRunDigest("context")
		}},
		{name: "CGGMP21 presign missing presign id", mutate: func(run *RunIntent) {
			run.Protocol = tss.ProtocolCGGMP21Secp256k1
			run.Kind = RunPresign
			run.Signers = tss.NewPartySet(1, 2)
			run.KeyGeneration = "gen-1"
			run.ContextDigest = testRunDigest("context")
		}},
		{name: "sign missing context digest", mutate: func(run *RunIntent) {
			run.Kind = RunSign
			run.Signers = tss.NewPartySet(1, 2)
			run.KeyGeneration = "gen-1"
		}},
		{name: "CGGMP21 sign missing presign id", mutate: func(run *RunIntent) {
			run.Protocol = tss.ProtocolCGGMP21Secp256k1
			run.Kind = RunSign
			run.Signers = tss.NewPartySet(1, 2)
			run.KeyGeneration = "gen-1"
			run.ContextDigest = testRunDigest("context")
		}},
		{name: "FROST sign with presign id", mutate: func(run *RunIntent) {
			run.Kind = RunSign
			run.Signers = tss.NewPartySet(1, 2)
			run.KeyGeneration = "gen-1"
			run.PresignID = "presign-1"
			run.ContextDigest = testRunDigest("context")
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run := testRunIntent(t, "run-1")
			tc.mutate(&run)
			if err := NewMemoryRunStore().CreateRun(context.Background(), run); !errors.Is(err, ErrInvalidRunIntent) {
				t.Fatalf("CreateRun got %v, want ErrInvalidRunIntent", err)
			}
		})
	}
}

type markStartedStore struct {
	RunStore
	markStarted func(context.Context, string, tss.PartyID) error
}

func (s *markStartedStore) MarkStarted(ctx context.Context, runID string, self tss.PartyID) error {
	return s.markStarted(ctx, runID, self)
}

func testRunIntent(t *testing.T, runID string) RunIntent {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return RunIntent{
		RunID:      runID,
		Protocol:   tss.ProtocolFROSTEd25519,
		Kind:       RunKeygen,
		SessionID:  sessionID,
		Parties:    tss.NewPartySet(1, 2, 3),
		Threshold:  2,
		KeyID:      "key-1",
		PlanDigest: testRunDigest("plan-digest"),
	}
}

func testKeygenRunResult(run RunIntent, label string) LocalRunResult {
	return LocalRunResult{
		KeyID:         run.KeyID,
		KeyGeneration: "gen-1",
		OutputDigest:  testRunDigest(label),
	}
}

func testRunDigest(label string) []byte {
	digest := sha256.Sum256([]byte(label))
	return digest[:]
}
