package secp256k1

import (
	"context"
	"errors"
	"fmt"
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
		defer session.Destroy()
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

	t.Run("completion_is_persisted_before_descriptor", func(t *testing.T) {
		sessions, stores := runAuthoritativePresign(t, shares, nil)
		for party, session := range sessions {
			descriptor, ok := session.Presign()
			if !ok || !session.Completed() {
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
			session.Destroy()
		}
	})

	t.Run("commit_failure_aborts_and_exposes_nothing", func(t *testing.T) {
		injected := errors.New("injected presign commit failure")
		sessions, stores, runErr := runAuthoritativePresignE(t, shares, map[tss.PartyID]error{1: injected})
		if !errors.Is(runErr, injected) {
			t.Fatalf("run error = %v, want injected commit failure", runErr)
		}
		failed := sessions[1]
		if failed == nil || !failed.aborted || failed.completed || failed.key != nil || failed.persistedPresign != nil {
			t.Fatal("commit failure did not destroy and abort the presign session")
		}
		if descriptor, ok := failed.Presign(); ok || descriptor.SlotID() != "" {
			t.Fatal("commit failure exposed a persisted descriptor")
		}
		if !slices.Contains(stores[1].calls, fmt.Sprintf("finish-%d", tssrun.LeaseAborted)) {
			t.Fatalf("commit failure did not abort lease: %v", stores[1].calls)
		}
		for _, session := range sessions {
			if session != nil {
				session.Destroy()
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
			out, err := sessions[party].Handle(testutil.DeliverEnvelope(env))
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
