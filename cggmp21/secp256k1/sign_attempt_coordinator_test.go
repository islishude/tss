package secp256k1

import (
	"context"
	"errors"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestSignAttemptCoordinatorClaimFailureDoesNotAdoptRecord(t *testing.T) {
	record := testSignAttemptRecord(t, 1)
	storeErr := errors.New("commit unavailable")
	store := &coordinatorTestStore{
		inner:     newTestSignAttemptStore(),
		commitErr: storeErr,
	}
	coordinator := newTestSignAttemptCoordinator(t, store, record.PresignContentID)
	_, err := coordinator.claim(context.Background(), record)
	if !errors.Is(err, ErrSignAttemptOutcomeUnknown) || !errors.Is(err, storeErr) {
		t.Fatalf("claim error = %v", err)
	}
	if _, ok := coordinator.record(); ok {
		t.Fatal("failed claim adopted a durable record")
	}
}

func TestSignAttemptCoordinatorDeliveryFailureDoesNotAdvanceRecord(t *testing.T) {
	record := testSignAttemptRecord(t, 1)
	store := &coordinatorTestStore{inner: newTestSignAttemptStore()}
	coordinator := newTestSignAttemptCoordinator(t, store, record.PresignContentID)
	if _, err := coordinator.claim(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	before, _ := coordinator.record()
	store.deliveryErr = errors.New("delivery unavailable")
	if _, err := coordinator.updateDelivery(context.Background(), nil, nil); !errors.Is(err, store.deliveryErr) {
		t.Fatalf("delivery error = %v", err)
	}
	after, _ := coordinator.record()
	if !before.Equal(after) {
		t.Fatal("failed delivery update advanced coordinator state")
	}
}

func TestSignAttemptCoordinatorCompletionFailureDoesNotAdvanceRecord(t *testing.T) {
	record := testSignAttemptRecord(t, 1)
	store := &coordinatorTestStore{inner: newTestSignAttemptStore()}
	coordinator := newTestSignAttemptCoordinator(t, store, record.PresignContentID)
	if _, err := coordinator.claim(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	before, _ := coordinator.record()
	store.completionErr = errors.New("completion unavailable")
	signature := Signature{
		R: secp.ScalarOne().Bytes(),
		S: secp.ScalarOne().Bytes(),
	}
	if _, err := coordinator.complete(context.Background(), signature); !errors.Is(err, store.completionErr) {
		t.Fatalf("completion error = %v", err)
	}
	after, _ := coordinator.record()
	if !before.Equal(after) {
		t.Fatal("failed completion advanced coordinator state")
	}
}

func TestSignAttemptCoordinatorBurnIsolatedFromOnlineState(t *testing.T) {
	record := testSignAttemptRecord(t, 1)
	store := newTestSignAttemptStore()
	coordinator := newTestSignAttemptCoordinator(t, store, record.PresignContentID)
	if err := coordinator.burn(context.Background(), "operator discard"); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.claim(context.Background(), record); !errors.Is(err, ErrSignAttemptBurned) {
		t.Fatalf("claim after burn error = %v", err)
	}
	if _, ok := coordinator.record(); ok {
		t.Fatal("burned coordinator adopted a record")
	}
}

func newTestSignAttemptCoordinator(t *testing.T, store SignAttemptStore, presignID []byte) *signAttemptCoordinator {
	t.Helper()
	coordinator, err := newSignAttemptCoordinator(store, presignHandle(presignID), DefaultSignAttemptStoreTimeout, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

type coordinatorTestStore struct {
	inner         SignAttemptStore
	commitErr     error
	deliveryErr   error
	completionErr error
	burnErr       error
	loadErr       error
}

func (s *coordinatorTestStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	if s.commitErr != nil {
		return SignAttemptCommit{}, s.commitErr
	}
	return s.inner.CommitSignAttempt(ctx, candidate)
}

func (s *coordinatorTestStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	if s.loadErr != nil {
		return SignAttemptRecord{}, s.loadErr
	}
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *coordinatorTestStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if s.deliveryErr != nil {
		return SignAttemptRecord{}, s.deliveryErr
	}
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *coordinatorTestStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	if s.completionErr != nil {
		return SignAttemptRecord{}, s.completionErr
	}
	return s.inner.CompleteSignAttempt(ctx, result)
}

func (s *coordinatorTestStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	if s.burnErr != nil {
		return s.burnErr
	}
	return s.inner.BurnPresign(ctx, burn)
}

var _ SignAttemptStore = (*coordinatorTestStore)(nil)
