package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss/tssrun"
)

type signAttemptCoordinator struct {
	store     tssrun.LifecycleStore
	lease     tssrun.RunLease
	query     tssrun.AttemptQuery
	attempt   tssrun.SignAttemptRecord
	timeout   time.Duration
	limits    Limits
	hasRecord bool
}

func newSignAttemptCoordinator(store tssrun.LifecycleStore, lease tssrun.RunLease, query tssrun.AttemptQuery, timeout time.Duration, limits Limits) (*signAttemptCoordinator, error) {
	if store == nil {
		return nil, errors.New("nil lifecycle store")
	}
	if err := query.Validate(); err != nil {
		return nil, err
	}
	if lease.Token != 0 {
		if lease.State != tssrun.RunLeaseActive ||
			lease.Binding != query.Binding ||
			lease.Kind != tssrun.RunSign {
			return nil, fmt.Errorf("%w: invalid sign run lease", ErrSignAttemptCorrupt)
		}
	}
	return &signAttemptCoordinator{
		store:   store,
		lease:   lease,
		query:   query.Clone(),
		timeout: durableStoreTimeout(timeout),
		limits:  limits,
	}, nil
}

func (c *signAttemptCoordinator) claim(ctx context.Context, outbox signAttemptOutbox, rawOutbox []byte) (tssrun.AttemptCommit, error) {
	if c == nil || c.store == nil {
		return tssrun.AttemptCommit{}, errors.New("sign attempt coordinator unavailable")
	}
	if outbox.SessionID != c.lease.SessionID ||
		outbox.PresignID != c.query.PresignID ||
		outbox.AttemptID != c.query.AttemptID ||
		!bytes.Equal(outbox.IntentDigest, c.query.IntentDigest) {
		return tssrun.AttemptCommit{}, fmt.Errorf("%w: sign outbox query mismatch", ErrSignAttemptCorrupt)
	}
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	commit, err := c.store.CommitSignAttempt(storeCtx, c.query.Binding, c.query.PresignID, tssrun.SignAttemptIntent{
		AttemptID:    c.query.AttemptID,
		SessionID:    c.lease.SessionID,
		IntentDigest: bytes.Clone(c.query.IntentDigest),
	}, rawOutbox)
	if err != nil {
		if lifecycleCommitKnownError(err) {
			return tssrun.AttemptCommit{}, err
		}
		if _, ok := errors.AsType[*tssrun.AttemptOutcomeUnknownError](err); ok {
			return tssrun.AttemptCommit{}, err
		}
		return tssrun.AttemptCommit{}, &tssrun.AttemptOutcomeUnknownError{
			Cause: err,
			Query: c.query.Clone(),
		}
	}
	if commit.Status != tssrun.AttemptCreated && commit.Status != tssrun.AttemptExistingSame {
		return tssrun.AttemptCommit{}, fmt.Errorf("%w: invalid lifecycle commit status", ErrSignAttemptCorrupt)
	}
	if err := c.acceptRecord(commit.Record); err != nil {
		return tssrun.AttemptCommit{}, err
	}
	commit.Record = c.attempt.Clone()
	return commit, nil
}

func (c *signAttemptCoordinator) markDelivered(ctx context.Context, delivery []byte) (tssrun.SignAttemptRecord, error) {
	if err := c.requireAttempt(); err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	record, err := c.store.MarkAttemptDelivered(storeCtx, c.query, delivery)
	if err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	if err := c.acceptRecord(record); err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	if err := c.finishLeaseIfTerminal(storeCtx); err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	return c.attempt.Clone(), nil
}

func (c *signAttemptCoordinator) complete(ctx context.Context, signature Signature) (tssrun.SignAttemptRecord, error) {
	if err := c.requireAttempt(); err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	completion, err := marshalSignAttemptCompletion(c.query.IntentDigest, signature, c.limits)
	if err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	defer clear(completion)
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	record, err := c.store.CompleteAttempt(storeCtx, c.query, completion)
	if err != nil {
		return tssrun.SignAttemptRecord{}, fmt.Errorf("persist sign attempt completion: %w", err)
	}
	if err := c.acceptRecord(record); err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	if err := c.finishLeaseIfTerminal(storeCtx); err != nil {
		return tssrun.SignAttemptRecord{}, err
	}
	return c.attempt.Clone(), nil
}

func (c *signAttemptCoordinator) abort(ctx context.Context, reason string) error {
	if err := c.requireAttempt(); err != nil {
		return err
	}
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	record, err := c.store.AbortAttempt(storeCtx, c.query, reason)
	if err != nil {
		return err
	}
	if err := c.acceptRecord(record); err != nil {
		return err
	}
	if c.lease.Token != 0 && c.lease.State == tssrun.RunLeaseActive {
		if err := c.store.FinishRunLease(storeCtx, c.lease, tssrun.LeaseAborted); err != nil {
			return err
		}
		c.lease.State = tssrun.RunLeaseAborted
	}
	return nil
}

func (c *signAttemptCoordinator) acceptRecord(record tssrun.SignAttemptRecord) error {
	if c == nil {
		return errors.New("nil sign attempt coordinator")
	}
	if !sameLifecycleAttemptQuery(record.Query(), c.query) {
		return fmt.Errorf("%w: durable lifecycle attempt identity mismatch", ErrSignAttemptCorrupt)
	}
	if c.lease.Token != 0 && record.Intent.SessionID != c.lease.SessionID {
		return fmt.Errorf("%w: durable lifecycle attempt session mismatch", ErrSignAttemptCorrupt)
	}
	if c.hasRecord && record.Intent.SessionID != c.attempt.Intent.SessionID {
		return fmt.Errorf("%w: durable lifecycle attempt session changed", ErrSignAttemptCorrupt)
	}
	if len(record.OutboxDigest) != sha256.Size {
		return fmt.Errorf("%w: invalid durable outbox digest", ErrSignAttemptCorrupt)
	}
	if len(record.ExactOutbox) != 0 {
		digest := sha256.Sum256(record.ExactOutbox)
		if !bytes.Equal(record.OutboxDigest, digest[:]) {
			return fmt.Errorf("%w: durable outbox digest mismatch", ErrSignAttemptCorrupt)
		}
	}
	if len(record.PresignMetadata) == 0 ||
		record.Delivered != (len(record.Delivery) != 0) ||
		record.Completed != (len(record.Completion) != 0) ||
		(record.Aborted && record.AbortReason == "") {
		return fmt.Errorf("%w: invalid durable attempt progress", ErrSignAttemptCorrupt)
	}
	if record.Aborted {
		return fmt.Errorf("%w: durable sign attempt aborted", tssrun.ErrAttemptConflict)
	}
	if c.hasRecord && !sameLifecycleAttemptQuery(c.attempt.Query(), record.Query()) {
		return fmt.Errorf("%w: durable attempt identity changed", ErrSignAttemptCorrupt)
	}
	c.attempt = record.Clone()
	c.hasRecord = true
	return nil
}

func (c *signAttemptCoordinator) requireAttempt() error {
	if c == nil || c.store == nil {
		return errors.New("sign attempt coordinator unavailable")
	}
	if !c.hasRecord {
		return errors.New("sign attempt coordinator has no durable attempt")
	}
	return nil
}

func (c *signAttemptCoordinator) finishLeaseIfTerminal(ctx context.Context) error {
	if c == nil || !c.hasRecord || !c.attempt.Terminal() ||
		c.lease.Token == 0 || c.lease.State != tssrun.RunLeaseActive {
		return nil
	}
	if err := c.store.FinishRunLease(ctx, c.lease, tssrun.LeaseCompleted); err != nil {
		return fmt.Errorf("finish sign run lease: %w", err)
	}
	c.lease.State = tssrun.RunLeaseCompleted
	return nil
}

func sameLifecycleAttemptQuery(a, b tssrun.AttemptQuery) bool {
	return a.Binding == b.Binding &&
		a.PresignID == b.PresignID &&
		a.AttemptID == b.AttemptID &&
		bytes.Equal(a.IntentDigest, b.IntentDigest)
}

func lifecycleCommitKnownError(err error) bool {
	return errors.Is(err, tssrun.ErrInvalidLifecycleRecord) ||
		errors.Is(err, tssrun.ErrGenerationNotCurrent) ||
		errors.Is(err, tssrun.ErrGenerationConflict) ||
		errors.Is(err, tssrun.ErrRunLeaseConflict) ||
		errors.Is(err, tssrun.ErrRunLeaseNotFound) ||
		errors.Is(err, tssrun.ErrPresignUnavailable) ||
		errors.Is(err, tssrun.ErrPresignBurned) ||
		errors.Is(err, tssrun.ErrAttemptConflict) ||
		errors.Is(err, tssrun.ErrAttemptNonDeterminism) ||
		errors.Is(err, tssrun.ErrLifecycleCorrupt)
}
