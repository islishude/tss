package secp256k1

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

func TestCGGMP21HandleCancellationRejectsBeforeMutation(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := startCGGMP21Keygen(tss.ThresholdConfig{
		Threshold: 2, Parties: tss.NewPartySet(1, 2), Self: 1, SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestSession(t, session)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := session.Handle(ctx, tss.InboundEnvelope{}); !errors.Is(err, context.Canceled) || len(out) != 0 {
		t.Fatalf("cancelled Handle out=%d err=%v", len(out), err)
	}
	if session.Status() != tssrun.SessionActive {
		t.Fatalf("cancelled Handle changed session status to %v", session.Status())
	}
}

func TestCGGMP21SignSessionConcurrentHandleStatusAbortAndClose(t *testing.T) {
	session := &SignSession{
		sessionCtx:       context.Background(),
		partials:         map[tss.PartyID]secp.Scalar{1: secp.ScalarOne()},
		partialEnvelopes: make(map[tss.PartyID]tss.Envelope),
		aborted:          true,
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _, _ = session.Handle(context.Background(), tss.InboundEnvelope{}) })
		wg.Go(func() { _ = session.Status() })
		wg.Go(func() { _ = session.Abort(context.Background(), "concurrent test abort") })
		wg.Go(func() { _ = session.Close(context.Background()) })
	}
	wg.Wait()
	if session.Status() != tssrun.SessionClosed {
		t.Fatalf("concurrent close left state %v", session.Status())
	}
}

type failOnceFinishLeaseStore struct {
	tssrun.LifecycleStore
	failed atomic.Bool
}

type failOnceRefreshFailureStore struct {
	tssrun.LifecycleStore
	failed atomic.Bool
}

func (s *failOnceRefreshFailureStore) MarkProtocolRefreshFailed(ctx context.Context, lease tssrun.RunLease, reason string) (tssrun.RefreshDisabledRecord, error) {
	if s.failed.CompareAndSwap(false, true) {
		return tssrun.RefreshDisabledRecord{}, errors.New("injected refresh marker failure")
	}
	return s.LifecycleStore.MarkProtocolRefreshFailed(ctx, lease, reason)
}

func (s *failOnceFinishLeaseStore) FinishRunLease(ctx context.Context, lease tssrun.RunLease, outcome tssrun.RunLeaseOutcome) error {
	if s.failed.CompareAndSwap(false, true) {
		return errors.New("injected finish failure")
	}
	return s.LifecycleStore.FinishRunLease(ctx, lease, outcome)
}

func TestCGGMP21PresignCloseRetriesDurableAbort(t *testing.T) {
	ctx := context.Background()
	base := tssrun.NewMemoryLifecycleStore()
	binding := tssrun.GenerationBinding{KeyID: "close-key", KeyGeneration: "gen-1", EpochID: tssrun.EpochID{1}}
	if _, err := base.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatal(err)
	}
	sessionID := testutilMustSessionID(t, 91)
	lease, err := base.AcquireRunLease(ctx, binding, tssrun.RunPresign, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	store := &failOnceFinishLeaseStore{LifecycleStore: base}
	session := &PresignSession{
		config: tss.ThresholdConfig{Self: 1, SessionID: sessionID}, lifecycleStore: store,
		lifecycleLease: lease, lifecycleTimeout: time.Second,
	}
	if err := session.Close(ctx); err == nil {
		t.Fatal("first Close hid durable abort failure")
	}
	if session.Status() != tssrun.SessionClosePending {
		t.Fatalf("failed Close status=%v, want SessionClosePending", session.Status())
	}
	if err := session.Close(ctx); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if session.Status() != tssrun.SessionClosed {
		t.Fatalf("retry Close status=%v, want SessionClosed", session.Status())
	}
}

func TestCGGMP21PresignProtocolAbortFailureBecomesClosePending(t *testing.T) {
	ctx := context.Background()
	base := tssrun.NewMemoryLifecycleStore()
	binding := tssrun.GenerationBinding{KeyID: "protocol-abort-key", KeyGeneration: "gen-1", EpochID: tssrun.EpochID{2}}
	if _, err := base.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatal(err)
	}
	sessionID := testutilMustSessionID(t, 92)
	lease, err := base.AcquireRunLease(ctx, binding, tssrun.RunPresign, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	store := &failOnceFinishLeaseStore{LifecycleStore: base}
	session := &PresignSession{
		config: tss.ThresholdConfig{Self: 1, SessionID: sessionID}, lifecycleStore: store,
		lifecycleLease: lease, lifecycleTimeout: time.Second,
	}
	cause := errors.New("terminal protocol rejection")
	if err := session.abortPresignRun(cause); !errors.Is(err, cause) {
		t.Fatalf("protocol abort error = %v", err)
	}
	if session.Status() != tssrun.SessionClosePending {
		t.Fatalf("failed protocol abort status=%v", session.Status())
	}
	if err := session.Abort(ctx, "retry terminal protocol rejection"); err != nil {
		t.Fatalf("retry protocol abort: %v", err)
	}
	queried, err := base.QueryRunLease(ctx, binding, tssrun.RunPresign, sessionID)
	if err != nil || queried.State != tssrun.RunLeaseAborted {
		t.Fatalf("retried protocol abort lease=%+v err=%v", queried, err)
	}
	if err := session.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCGGMP21RefreshTerminalFailureCloseRetriesMarker(t *testing.T) {
	ctx := context.Background()
	base := tssrun.NewMemoryLifecycleStore()
	binding := tssrun.GenerationBinding{KeyID: "refresh-marker-key", KeyGeneration: "gen-1", EpochID: tssrun.EpochID{3}}
	if _, err := base.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatal(err)
	}
	sessionID := testutilMustSessionID(t, 93)
	lease, err := base.AcquireRunLease(ctx, binding, tssrun.RunRefresh, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	store := &failOnceRefreshFailureStore{LifecycleStore: base}
	session := &RefreshSession{
		cfg: tss.ThresholdConfig{Self: 1, SessionID: sessionID}, lifecycleStore: store,
		lifecycleLease: lease, lifecycleTimeout: time.Second,
	}
	if err := session.terminalFigure7Failure(&Figure7Failure{Class: Figure7FailureDecryptionError, Reporter: 1, Accused: 2}); err == nil {
		t.Fatal("terminal refresh failure hid durable marker error")
	}
	if session.Status() != tssrun.SessionClosePending {
		t.Fatalf("refresh marker failure status=%v", session.Status())
	}
	if err := session.Close(ctx); err != nil {
		t.Fatalf("retry refresh close: %v", err)
	}
	if session.Status() != tssrun.SessionClosed {
		t.Fatalf("refresh retry close status=%v", session.Status())
	}
	if _, err := base.AcquireRunLease(ctx, binding, tssrun.RunRefresh, testutilMustSessionID(t, 94)); !errors.Is(err, tssrun.ErrRefreshDisabled) {
		t.Fatalf("refresh failure marker was not durable: %v", err)
	}
}

func TestCGGMP21ReshareTerminalAbortCloseRetriesLease(t *testing.T) {
	ctx := context.Background()
	base := tssrun.NewMemoryLifecycleStore()
	binding := tssrun.GenerationBinding{KeyID: "reshare-abort-key", KeyGeneration: "gen-1", EpochID: tssrun.EpochID{4}}
	if _, err := base.InstallInitialGeneration(ctx, binding, []byte("generation"), nil); err != nil {
		t.Fatal(err)
	}
	sessionID := testutilMustSessionID(t, 95)
	lease, err := base.AcquireRunLease(ctx, binding, tssrun.RunReshare, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	store := &failOnceFinishLeaseStore{LifecycleStore: base}
	session := &ReshareSession{
		cfg: tss.ThresholdConfig{Self: 1, SessionID: sessionID}, selfID: 1,
		lifecycleStore: store, lifecycleLease: lease, lifecycleTimeout: time.Second,
		aborted: true, completed: true,
	}
	if err := session.commitPendingReshareLifecycle(ctx); err == nil {
		t.Fatal("terminal reshare abort hid durable lease error")
	}
	if session.Status() != tssrun.SessionClosePending {
		t.Fatalf("reshare abort failure status=%v", session.Status())
	}
	if err := session.Close(ctx); err != nil {
		t.Fatalf("retry reshare close: %v", err)
	}
	queried, err := base.QueryRunLease(ctx, binding, tssrun.RunReshare, sessionID)
	if err != nil || queried.State != tssrun.RunLeaseAborted {
		t.Fatalf("retried reshare abort lease=%+v err=%v", queried, err)
	}
}

func testutilMustSessionID(t *testing.T, seed byte) tss.SessionID {
	t.Helper()
	var id tss.SessionID
	id[0] = seed
	if !id.Valid() {
		t.Fatal("invalid deterministic session ID")
	}
	return id
}
