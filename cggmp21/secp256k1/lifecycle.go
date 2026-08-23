package secp256k1

import (
	"context"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

func validateSessionDisposition(ctx context.Context, reason string) error {
	if ctx == nil {
		return errors.New("nil session disposition context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if reason == "" {
		return errors.New("session abort reason must not be empty")
	}
	return nil
}

// Abort terminally aborts an active keygen session and clears staged secrets.
func (s *KeygenSession) Abort(ctx context.Context, reason string) error {
	if err := validateSessionDisposition(ctx, reason); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.aborted {
		return nil
	}
	if s.completed {
		return tssrun.ErrRunCompleted
	}
	s.abort()
	return nil
}

// Close clears all keygen-session state after an authoritative disposition.
func (s *KeygenSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil session close context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.completed && !s.aborted {
		s.abort()
	}
	if s.keyShare != nil {
		s.keyShare.Destroy()
		s.keyShare = nil
	}
	s.closed = true
	return nil
}

// Abort clears presign witnesses and durably aborts the exact active lease.
func (s *PresignSession) Abort(ctx context.Context, reason string) error {
	if err := validateSessionDisposition(ctx, reason); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abortDispositionLocked(ctx, reason)
}

func (s *PresignSession) abortDispositionLocked(ctx context.Context, _ string) error {
	if s.closed {
		return nil
	}
	if s.lifecycleCandidate != nil {
		return tssrun.ErrLifecycleCommitPending
	}
	if s.completed {
		return tssrun.ErrRunCompleted
	}
	if !s.aborted {
		s.abort()
	}
	store := s.lifecycleStore
	lease := s.lifecycleLease
	timeout := s.lifecycleTimeout
	finished := s.leaseFinished
	if !finished && store != nil && lease.Token != 0 {
		storeCtx, cancel := durableStoreContext(ctx, timeout)
		err := store.FinishRunLease(storeCtx, lease, tssrun.LeaseAborted)
		cancel()
		if err != nil {
			s.closePending = true
			return fmt.Errorf("abort presign run lease: %w", err)
		}
		s.leaseFinished = true
		s.closePending = false
	}
	return nil
}

// Close clears a presign session after its durable disposition is known.
func (s *PresignSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil session close context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.lifecycleCandidate != nil {
		return tssrun.ErrLifecycleCommitPending
	}
	completed := s.completed
	pending := !s.leaseFinished && (s.closePending || !s.aborted)
	if pending {
		if err := s.abortDispositionLocked(ctx, "presign session closed by caller"); err != nil {
			return err
		}
	}
	if completed || !s.closed {
		s.abort()
	}
	s.closed = true
	s.closePending = false
	return nil
}

// Abort durably burns the committed online-sign attempt before clearing local state.
func (s *SignSession) Abort(ctx context.Context, reason string) error {
	if err := validateSessionDisposition(ctx, reason); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abortDispositionLocked(ctx, reason)
}

func (s *SignSession) abortDispositionLocked(ctx context.Context, reason string) error {
	if s.closed {
		return nil
	}
	if s.completed {
		return tssrun.ErrRunCompleted
	}
	var abortErr error
	if s.coordinator != nil {
		abortErr = s.coordinator.abort(ctx, reason)
	}
	s.abort()
	if abortErr != nil {
		s.closePending = true
		return fmt.Errorf("abort online-sign attempt: %w", abortErr)
	}
	s.closePending = false
	return nil
}

// Close clears an online-sign session after its attempt disposition is authoritative.
func (s *SignSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil session close context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	needsAbort := !s.completed && (!s.aborted || s.closePending)
	if needsAbort {
		if err := s.abortDispositionLocked(ctx, "online-sign session closed by caller"); err != nil {
			return err
		}
	}
	s.abort()
	clear(s.publicKey)
	s.publicKey = nil
	if s.signature != nil {
		clear(s.signature.R)
		clear(s.signature.S)
	}
	s.signature = nil
	clear(s.attempt.PresignMetadata)
	clear(s.attempt.ExactOutbox)
	clear(s.attempt.OutboxDigest)
	clear(s.attempt.Delivery)
	clear(s.attempt.Completion)
	s.attempt = tssrun.SignAttemptRecord{}
	s.closed = true
	s.closePending = false
	return nil
}

func clearScalarMap(xs map[tss.PartyID]secp.Scalar) {
	for id := range xs {
		xs[id] = secp.ScalarZero()
		delete(xs, id)
	}
}
