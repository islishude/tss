//go:build integration

package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

type failOnceRefreshCutoverStore struct {
	tssrun.LifecycleStore

	mu      sync.Mutex
	failErr error
	calls   int
}

func (s *failOnceRefreshCutoverStore) CommitCutover(
	ctx context.Context,
	fence tssrun.CutoverFence,
	targetBlob, targetMetadata []byte,
) (tssrun.GenerationRecord, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	if call == 1 {
		return tssrun.GenerationRecord{}, s.failErr
	}
	return s.LifecycleStore.CommitCutover(ctx, fence, targetBlob, targetMetadata)
}

func (s *failOnceRefreshCutoverStore) commitCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestCGGMP21_Refresh_LifecycleRetryRetainsSessionAndCommitsOnce(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	source := shares[1]
	oldPublicKey := mustKeySharePublicKey(t, source)
	limits := testLimits()
	securityParams := testSecurityParams()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewRefreshPlan(RefreshPlanOption{
		OldKey:         source,
		SessionID:      sessionID,
		Limits:         &limits,
		SecurityParams: &securityParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	epochID, err := tssrun.NewEpochID(source.state.Epoch.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	sourceBinding := tssrun.GenerationBinding{
		KeyID:         "refresh-retry-key",
		KeyGeneration: "refresh-retry-source",
		EpochID:       epochID,
	}
	baseStore := newTestLifecycleStore()
	transientErr := errors.New("transient cutover failure")
	store := &failOnceRefreshCutoverStore{
		LifecycleStore: baseStore,
		failErr:        transientErr,
	}
	if err := installTestLifecycleGeneration(context.Background(), store, source, sourceBinding, limits); err != nil {
		t.Fatal(err)
	}

	session, out, err := StartRefresh(plan, RefreshRuntime{
		Local: tss.LocalConfig{
			Self:           source.PartyID(),
			EnvelopeSigner: testEnvelopeIdentity{},
		},
		Guard:               testCGGMP21Guard(source.PartyID(), source.state.Parties, sessionID),
		LifecycleStore:      store,
		Binding:             sourceBinding,
		TargetKeyGeneration: "refresh-retry-target",
	})
	if !errors.Is(err, transientErr) {
		t.Fatalf("StartRefresh error = %v, want transient cutover failure", err)
	}
	if session == nil {
		t.Fatal("StartRefresh discarded the retryable session")
	}
	defer session.Destroy()
	if len(out) != 0 {
		t.Fatalf("StartRefresh exposed %d envelopes before durable cutover", len(out))
	}
	if refreshed, ok := session.KeyShare(); ok {
		refreshed.Destroy()
		t.Fatal("refreshed share became visible before durable cutover")
	}
	current, err := baseStore.LoadCurrentGeneration(context.Background(), sourceBinding.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(current.Blob)
	defer clear(current.Metadata)
	if current.Binding != sourceBinding {
		t.Fatalf("current binding changed before retry: got %+v, want %+v", current.Binding, sourceBinding)
	}

	retryOut, err := session.RetryLifecycleCommit(context.Background())
	if err != nil {
		t.Fatalf("RetryLifecycleCommit: %v", err)
	}
	defer clearEnvelopePayloads(retryOut)
	if len(retryOut) != 1 {
		t.Fatalf("RetryLifecycleCommit returned %d envelopes, want the one withheld confirmation", len(retryOut))
	}
	refreshed, ok := session.KeyShare()
	if !ok {
		t.Fatal("refreshed share unavailable after durable cutover")
	}
	defer refreshed.Destroy()
	if !bytes.Equal(mustKeySharePublicKey(t, refreshed), oldPublicKey) {
		t.Fatal("refresh changed the group public key")
	}

	committed, err := baseStore.LoadCurrentGeneration(context.Background(), sourceBinding.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(committed.Blob)
	defer clear(committed.Metadata)
	if committed.Binding.KeyGeneration != "refresh-retry-target" || committed.Binding == sourceBinding {
		t.Fatalf("retry did not install the target generation: got %+v", committed.Binding)
	}

	secondOut, err := session.RetryLifecycleCommit(context.Background())
	if err != nil {
		t.Fatalf("second RetryLifecycleCommit: %v", err)
	}
	if len(secondOut) != 0 {
		defer clearEnvelopePayloads(secondOut)
		t.Fatalf("second retry replayed %d envelopes", len(secondOut))
	}
	if got := store.commitCalls(); got != 2 {
		t.Fatalf("CommitCutover calls = %d, want one failed attempt and one successful retry", got)
	}
}
