//go:build integration

package secp256k1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/tssrun"
)

type recordingPresignLifecycleStore struct {
	tssrun.LifecycleStore
	calls      []string
	failCommit error
}

type failAfterFirstPresignEnvelopeSigner struct {
	calls int
	err   error
}

func (s *failAfterFirstPresignEnvelopeSigner) SignEnvelopeDigest([32]byte) ([]byte, error) {
	s.calls++
	if s.calls > 1 {
		return nil, s.err
	}
	return []byte{1}, nil
}

func (s *recordingPresignLifecycleStore) LoadCurrentGeneration(ctx context.Context, keyID string) (tssrun.GenerationRecord, error) {
	s.calls = append(s.calls, "load")
	return s.LifecycleStore.LoadCurrentGeneration(ctx, keyID)
}

func (s *recordingPresignLifecycleStore) AcquireRunLease(ctx context.Context, binding tssrun.GenerationBinding, kind tssrun.RunKind, sessionID tss.SessionID) (tssrun.RunLease, error) {
	s.calls = append(s.calls, "acquire")
	return s.LifecycleStore.AcquireRunLease(ctx, binding, kind, sessionID)
}

func (s *recordingPresignLifecycleStore) CommitAvailablePresignFromLease(ctx context.Context, lease tssrun.RunLease, presignID string, blob, metadata []byte) error {
	s.calls = append(s.calls, "commit")
	if s.failCommit != nil {
		return s.failCommit
	}
	return s.LifecycleStore.CommitAvailablePresignFromLease(ctx, lease, presignID, blob, metadata)
}

func (s *recordingPresignLifecycleStore) FinishRunLease(ctx context.Context, lease tssrun.RunLease, outcome tssrun.RunLeaseOutcome) error {
	s.calls = append(s.calls, fmt.Sprintf("finish-%d", outcome))
	return s.LifecycleStore.FinishRunLease(ctx, lease, outcome)
}

func TestPresignRuntimeLoadsClaimsAndPersistsAuthoritatively(t *testing.T) {
	shares, err := runSecpKeygen(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, share := range shares {
			share.Destroy()
		}
	}()

	t.Run("lease_precedes_visible_envelopes", func(t *testing.T) {
		sessionID := mustPresignRuntimeSessionID(t)
		plan := testAuthoritativePresignPlan(t, shares[1], sessionID)
		store, runtime := testAuthoritativePresignRuntime(t, shares[1], plan, nil)
		session, out, err := StartPresign(plan, runtime)
		if err != nil {
			t.Fatal(err)
		}
		defer closeTestSession(t, session)
		if len(out) == 0 {
			t.Fatal("StartPresign returned no Figure 8 envelopes")
		}
		if !slices.Equal(store.calls, []string{"load", "acquire"}) {
			t.Fatalf("lifecycle calls before output = %v", store.calls)
		}
		if session.key == shares[1] || !session.ownsKey || session.lifecycleLease.Kind != tssrun.RunPresign {
			t.Fatal("session did not own the exact lifecycle-loaded generation and lease")
		}
		if _, ok := session.Presign(); ok {
			t.Fatal("presign descriptor visible before durable completion")
		}
	})

	t.Run("preparation_failure_aborts_lease_without_output", func(t *testing.T) {
		// Exhaust randomness during each nonce sample or the first MtA opening.
		for _, available := range []int64{0, 32, 64, 96, 128, 160} {
			t.Run(fmt.Sprintf("random_bytes_%d", available), func(t *testing.T) {
				sessionID := mustPresignRuntimeSessionID(t)
				plan := testAuthoritativePresignPlan(t, shares[1], sessionID)
				store, runtime := testAuthoritativePresignRuntime(t, shares[1], plan, nil)
				runtime.Local.Rand = io.LimitReader(testutil.DeterministicReader(314), available)
				session, out, err := StartPresign(plan, runtime)
				if !errors.Is(err, io.EOF) || session != nil || len(out) != 0 {
					t.Fatalf("failed preparation session=%v out=%d err=%v", session != nil, len(out), err)
				}
				if !slices.Equal(store.calls, []string{"load", "acquire", fmt.Sprintf("finish-%d", tssrun.LeaseAborted)}) {
					t.Fatalf("failed preparation lifecycle calls = %v", store.calls)
				}
				lease, err := store.QueryRunLease(context.Background(), runtime.Binding, tssrun.RunPresign, sessionID)
				if err != nil || lease.State != tssrun.RunLeaseAborted {
					t.Fatalf("failed preparation lease state=%v err=%v", lease.State, err)
				}
				slotID, err := PresignSlotID(plan.state.presignID)
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := store.PreparePresignCandidate(context.Background(), runtime.Binding, slotID)
				clear(candidate.Blob)
				clear(candidate.Metadata)
				if !errors.Is(err, tssrun.ErrPresignUnavailable) {
					t.Fatalf("failed preparation candidate error = %v", err)
				}
			})
		}
	})

	t.Run("post-construction_failure_retains_session_when_abort_is_not_durable", func(t *testing.T) {
		sessionID := mustPresignRuntimeSessionID(t)
		plan := testAuthoritativePresignPlan(t, shares[1], sessionID)
		store, runtime := testAuthoritativePresignRuntime(t, shares[1], plan, nil)
		finishStore := &failOnceFinishLeaseStore{LifecycleStore: store}
		runtime.LifecycleStore = finishStore
		signErr := errors.New("injected post-construction envelope failure")
		runtime.Local.EnvelopeSigner = &failAfterFirstPresignEnvelopeSigner{err: signErr}
		session, out, err := StartPresign(plan, runtime)
		if !errors.Is(err, signErr) || session == nil || len(out) != 0 {
			t.Fatalf("StartPresign session=%v out=%d err=%v", session != nil, len(out), err)
		}
		if session.Status() != tssrun.SessionClosePending {
			t.Fatalf("failed start status=%v", session.Status())
		}
		if err := session.Close(context.Background()); err != nil {
			t.Fatalf("retry Close after failed start: %v", err)
		}
		queried, err := store.QueryRunLease(context.Background(), runtime.Binding, tssrun.RunPresign, sessionID)
		if err != nil || queried.State != tssrun.RunLeaseAborted {
			t.Fatalf("retried failed-start lease=%+v err=%v", queried, err)
		}
	})

	t.Run("completion_is_persisted_before_descriptor", func(t *testing.T) {
		sessions, stores := runAuthoritativePresign(t, shares, nil)
		for party, session := range sessions {
			descriptor, ok := session.Presign()
			if !ok || session.Status() != tssrun.SessionSucceeded {
				t.Fatalf("party %d did not expose a durable descriptor", party)
			}
			if session.key != nil || !session.leaseFinished {
				t.Fatalf("party %d retained lifecycle key or active lease after completion", party)
			}
			if !slices.Equal(stores[party].calls, []string{"load", "acquire", "commit"}) {
				t.Fatalf("party %d lifecycle calls = %v", party, stores[party].calls)
			}
			candidate, err := stores[party].PreparePresignCandidate(context.Background(), session.lifecycleLease.Binding, descriptor.SlotID())
			if err != nil {
				t.Fatalf("party %d persisted candidate: %v", party, err)
			}
			if len(candidate.Blob) == 0 || len(candidate.Metadata) == 0 {
				t.Fatalf("party %d persisted an empty candidate", party)
			}
			clear(candidate.Blob)
			clear(candidate.Metadata)
			again, ok := session.Presign()
			if !ok || again.SlotID() != descriptor.SlotID() {
				t.Fatalf("party %d descriptor accessor is not repeatable", party)
			}
			closeTestSession(t, session)
		}
	})

	t.Run("commit_failure_retains_exact_candidate_for_retry", func(t *testing.T) {
		injected := errors.New("injected presign commit failure")
		sessions, stores, runErr := runAuthoritativePresignE(t, shares, map[tss.PartyID]error{1: injected})
		if !errors.Is(runErr, injected) {
			t.Fatalf("run error = %v, want injected commit failure", runErr)
		}
		failed := sessions[1]
		if failed == nil || failed.aborted || failed.completed || failed.lifecycleCandidate == nil || failed.persistedPresign != nil || failed.Status() != tssrun.SessionCommitPending {
			t.Fatal("commit failure did not retain one pending presign candidate")
		}
		if descriptor, ok := failed.Presign(); ok || descriptor.SlotID() != "" {
			t.Fatal("commit failure exposed a persisted descriptor")
		}
		if slices.Contains(stores[1].calls, fmt.Sprintf("finish-%d", tssrun.LeaseAborted)) {
			t.Fatalf("commit-pending failure incorrectly aborted its lease: %v", stores[1].calls)
		}
		if err := failed.Close(context.Background()); !errors.Is(err, tssrun.ErrLifecycleCommitPending) {
			t.Fatalf("close pending presign candidate = %v", err)
		}
		stores[1].failCommit = nil
		if err := failed.RetryLifecycleCommit(context.Background()); err != nil {
			t.Fatalf("retry exact presign commit: %v", err)
		}
		if descriptor, ok := failed.Presign(); !ok || descriptor.SlotID() == "" || failed.Status() != tssrun.SessionSucceeded {
			t.Fatal("exact retry did not expose the persisted descriptor")
		}
		for _, session := range sessions {
			if session != nil {
				closeTestSession(t, session)
			}
		}
	})
}

func testAuthoritativePresignPlan(t testing.TB, key *KeyShare, sessionID tss.SessionID) *PresignPlan {
	t.Helper()
	plan, err := NewPresignPlan(PresignPlanOption{
		Key: key, SessionID: sessionID, PresignID: sessionID[:], Signers: tss.NewPartySet(1, 2),
		Context: testPresignContext(), Limits: testLimitsPtr(), SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testAuthoritativePresignRuntime(t testing.TB, key *KeyShare, plan *PresignPlan, commitErr error) (*recordingPresignLifecycleStore, PresignRuntime) {
	t.Helper()
	epochID, err := tssrun.NewEpochID(key.state.Epoch.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	binding := tssrun.GenerationBinding{
		KeyID: plan.state.context.KeyID, KeyGeneration: tssrun.KeyGeneration(fmt.Sprintf("authoritative-%d", key.state.Party)), EpochID: epochID,
	}
	blob, err := key.MarshalBinaryWithLimits(plan.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	memory := tssrun.NewMemoryLifecycleStore()
	if _, err := memory.InstallInitialGeneration(context.Background(), binding, blob, key.state.PlanHash); err != nil {
		t.Fatal(err)
	}
	store := &recordingPresignLifecycleStore{LifecycleStore: memory, failCommit: commitErr}
	return store, PresignRuntime{
		Local:          tss.LocalConfig{Self: key.state.Party},
		Guard:          testCGGMP21Guard(key.state.Party, key.state.Parties, plan.state.sessionID),
		LifecycleStore: store, Binding: binding,
	}
}

func runAuthoritativePresign(t testing.TB, shares map[tss.PartyID]*KeyShare, failures map[tss.PartyID]error) (map[tss.PartyID]*PresignSession, map[tss.PartyID]*recordingPresignLifecycleStore) {
	t.Helper()
	sessions, stores, err := runAuthoritativePresignE(t, shares, failures)
	if err != nil {
		t.Fatal(err)
	}
	return sessions, stores
}

func runAuthoritativePresignE(t testing.TB, shares map[tss.PartyID]*KeyShare, failures map[tss.PartyID]error) (map[tss.PartyID]*PresignSession, map[tss.PartyID]*recordingPresignLifecycleStore, error) {
	t.Helper()
	sessionID := mustPresignRuntimeSessionID(t)
	sessions := make(map[tss.PartyID]*PresignSession, len(shares))
	stores := make(map[tss.PartyID]*recordingPresignLifecycleStore, len(shares))
	queue := make([]tss.Envelope, 0)
	for _, party := range tss.NewPartySet(1, 2) {
		plan := testAuthoritativePresignPlan(t, shares[party], sessionID)
		store, runtime := testAuthoritativePresignRuntime(t, shares[party], plan, failures[party])
		session, out, err := StartPresign(plan, runtime)
		if err != nil {
			return sessions, stores, err
		}
		sessions[party] = session
		stores[party] = store
		queue = append(queue, out...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, party := range tss.NewPartySet(1, 2) {
			if party == env.From || (env.To != tss.BroadcastPartyId && env.To != party) {
				continue
			}
			out, err := sessions[party].Handle(context.Background(), testutil.DeliverEnvelope(env))
			if err != nil {
				return sessions, stores, err
			}
			queue = append(queue, out...)
		}
	}
	return sessions, stores, nil
}

func mustPresignRuntimeSessionID(t testing.TB) tss.SessionID {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return sessionID
}
