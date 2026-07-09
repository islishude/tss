//go:build integration

package secp256k1

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

type fixedErrSignAttemptStore struct {
	err error
}

type loadErrSignAttemptStore struct {
	err error
}

func (s loadErrSignAttemptStore) LoadSignAttempt(context.Context, []byte) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, s.err
}

func (s loadErrSignAttemptStore) CommitSignAttempt(context.Context, SignAttemptRecord) (SignAttemptCommit, error) {
	return SignAttemptCommit{}, errors.New("unexpected commit after load error")
}

func (s loadErrSignAttemptStore) UpdateSignAttemptDelivery(context.Context, SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, errors.New("unexpected delivery update after load error")
}

func (s loadErrSignAttemptStore) CompleteSignAttempt(context.Context, SignAttemptResult) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, errors.New("unexpected completion after load error")
}

func (s loadErrSignAttemptStore) BurnPresign(context.Context, SignAttemptBurn) error {
	return errors.New("unexpected burn after load error")
}

func (s fixedErrSignAttemptStore) LoadSignAttempt(context.Context, []byte) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, ErrSignAttemptNotFound
}

func (s fixedErrSignAttemptStore) CommitSignAttempt(context.Context, SignAttemptRecord) (SignAttemptCommit, error) {
	return SignAttemptCommit{}, s.err
}

func (s fixedErrSignAttemptStore) UpdateSignAttemptDelivery(context.Context, SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, s.err
}

func (s fixedErrSignAttemptStore) CompleteSignAttempt(context.Context, SignAttemptResult) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, s.err
}

func (s fixedErrSignAttemptStore) BurnPresign(context.Context, SignAttemptBurn) error {
	return s.err
}

type outcomeUnknownSignAttemptStore struct {
	inner *testSignAttemptStore
	err   error
	once  bool
}

type completionOutcomeUnknownStore struct {
	inner *testSignAttemptStore
	err   error
	once  bool
}

type loadCountingSignAttemptStore struct {
	inner *testSignAttemptStore
	loads atomic.Int32
}

func (s *loadCountingSignAttemptStore) loadCount() int {
	return int(s.loads.Load())
}

func (s *loadCountingSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	s.loads.Add(1)
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *loadCountingSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	return s.inner.CommitSignAttempt(ctx, candidate)
}

func (s *loadCountingSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *loadCountingSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	return s.inner.CompleteSignAttempt(ctx, result)
}

func (s *loadCountingSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	return s.inner.BurnPresign(ctx, burn)
}

func (s *completionOutcomeUnknownStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *completionOutcomeUnknownStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	return s.inner.CommitSignAttempt(ctx, candidate)
}

func (s *completionOutcomeUnknownStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *completionOutcomeUnknownStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	record, err := s.inner.CompleteSignAttempt(ctx, result)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if !s.once {
		s.once = true
		return SignAttemptRecord{}, s.err
	}
	return record, nil
}

func (s *completionOutcomeUnknownStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	return s.inner.BurnPresign(ctx, burn)
}

func (s *outcomeUnknownSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *outcomeUnknownSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	commit, err := s.inner.CommitSignAttempt(ctx, candidate)
	if err != nil {
		return SignAttemptCommit{}, err
	}
	if !s.once {
		s.once = true
		return SignAttemptCommit{}, s.err
	}
	return commit, nil
}

func (s *outcomeUnknownSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *outcomeUnknownSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	return s.inner.CompleteSignAttempt(ctx, result)
}

func (s *outcomeUnknownSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	return s.inner.BurnPresign(ctx, burn)
}

func startSignDigestMustSucceed(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := StartSignDigest(share, presign, sessionID, digest)
	if err != nil {
		t.Fatalf("StartSignDigest: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("StartSignDigest returned no signing partial")
	}
}

func startSignDigestMustBeConsumed(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := StartSignDigest(share, presign, sessionID, digest)
	if session != nil || out != nil {
		t.Fatal("consumed presign returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
}

func startSignDigestWithStoreMustBeConsumed(t *testing.T, share *KeyShare, presign *Presign, digest []byte, store SignAttemptStore) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := StartSignDigestWithStore(share, presign, sessionID, digest, store)
	if session != nil || out != nil {
		t.Fatal("consumed store returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
}
