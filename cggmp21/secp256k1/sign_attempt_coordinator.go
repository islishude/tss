package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/islishude/tss"
)

// presignHandle is the store-facing identity boundary for one presign. Its
// current bytes come from Presign.id(); a future persisted non-secret UID can
// replace that derivation without changing online-sign state transitions.
type presignHandle []byte

func newPresignHandle(presign *Presign) (presignHandle, error) {
	if presign == nil || presign.state == nil {
		return nil, errors.New("nil presign")
	}
	handle := presignHandle(presign.id())
	if len(handle) != sha256.Size {
		return nil, errors.New("invalid presign handle")
	}
	return slices.Clone(handle), nil
}

type signAttemptCoordinator struct {
	store     SignAttemptStore
	handle    presignHandle
	attempt   SignAttemptRecord
	timeout   time.Duration
	limits    Limits
	hasRecord bool
}

func newSignAttemptCoordinator(store SignAttemptStore, handle presignHandle, timeout time.Duration, limits Limits) (*signAttemptCoordinator, error) {
	if store == nil {
		return nil, errors.New("nil sign attempt store")
	}
	if len(handle) != sha256.Size {
		return nil, errors.New("invalid presign handle")
	}
	return &signAttemptCoordinator{
		store:   store,
		handle:  slices.Clone(handle),
		timeout: durableStoreTimeout(timeout),
		limits:  limits,
	}, nil
}

func (c *signAttemptCoordinator) claim(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	if err := c.validateCandidateIdentity(candidate); err != nil {
		return SignAttemptCommit{}, err
	}
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	commit, err := c.store.CommitSignAttempt(storeCtx, candidate)
	if err != nil {
		if signAttemptConsumedError(err) {
			return SignAttemptCommit{}, err
		}
		return SignAttemptCommit{}, fmt.Errorf("%w: %w", ErrSignAttemptOutcomeUnknown, err)
	}
	if commit.Status != SignAttemptCreated && commit.Status != SignAttemptExistingSame {
		return SignAttemptCommit{}, fmt.Errorf("%w: invalid commit status", ErrSignAttemptCorrupt)
	}
	if err := c.acceptRecord(commit.Record); err != nil {
		return SignAttemptCommit{}, err
	}
	commit.Record = c.attempt.Clone()
	return commit, nil
}

func (c *signAttemptCoordinator) load(ctx context.Context) (SignAttemptRecord, error) {
	if c == nil || c.store == nil {
		return SignAttemptRecord{}, errors.New("sign attempt coordinator unavailable")
	}
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	record, err := c.store.LoadSignAttempt(ctx, slices.Clone(c.handle))
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if err := c.acceptRecord(record); err != nil {
		return SignAttemptRecord{}, err
	}
	return c.attempt.Clone(), nil
}

func (c *signAttemptCoordinator) updateDelivery(ctx context.Context, ack *tss.BroadcastAck, certificate *tss.BroadcastCertificate) (SignAttemptRecord, error) {
	if err := c.requireAttempt(); err != nil {
		return SignAttemptRecord{}, err
	}
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	updated, err := c.store.UpdateSignAttemptDelivery(storeCtx, SignAttemptDeliveryUpdate{
		PresignID:   slices.Clone(c.attempt.PresignID),
		AttemptHash: slices.Clone(c.attempt.AttemptHash),
		Ack:         ack,
		Certificate: certificate,
	})
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if err := c.acceptRecord(updated); err != nil {
		return SignAttemptRecord{}, err
	}
	return c.attempt.Clone(), nil
}

func (c *signAttemptCoordinator) complete(ctx context.Context, signature Signature) (SignAttemptRecord, error) {
	if err := c.requireAttempt(); err != nil {
		return SignAttemptRecord{}, err
	}
	storeCtx, cancel := durableStoreContext(ctx, c.timeout)
	defer cancel()
	completed, err := c.store.CompleteSignAttempt(storeCtx, SignAttemptResult{
		PresignID:   slices.Clone(c.attempt.PresignID),
		AttemptHash: slices.Clone(c.attempt.AttemptHash),
		Signature: Signature{
			R:          slices.Clone(signature.R),
			S:          slices.Clone(signature.S),
			RecoveryID: signature.RecoveryID,
		},
	})
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("persist sign attempt completion: %w", err)
	}
	if !completed.Completed ||
		!bytes.Equal(completed.SignatureR, signature.R) ||
		!bytes.Equal(completed.SignatureS, signature.S) ||
		completed.SignatureRecoveryID != signature.RecoveryID {
		return SignAttemptRecord{}, fmt.Errorf("%w: completion record mismatch", ErrSignAttemptCorrupt)
	}
	if err := c.acceptRecord(completed); err != nil {
		return SignAttemptRecord{}, err
	}
	return c.attempt.Clone(), nil
}

func (c *signAttemptCoordinator) burn(ctx context.Context, reason string) error {
	if c == nil || c.store == nil {
		return errors.New("sign attempt coordinator unavailable")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	return c.store.BurnPresign(ctx, SignAttemptBurn{
		PresignID: slices.Clone(c.handle),
		Reason:    reason,
	})
}

func (c *signAttemptCoordinator) record() (SignAttemptRecord, bool) {
	if c == nil || !c.hasRecord {
		return SignAttemptRecord{}, false
	}
	return c.attempt.Clone(), true
}

func (c *signAttemptCoordinator) validateCandidateIdentity(candidate SignAttemptRecord) error {
	if c == nil || c.store == nil {
		return errors.New("sign attempt coordinator unavailable")
	}
	if !bytes.Equal(candidate.PresignID, c.handle) {
		return fmt.Errorf("%w: candidate presign identity mismatch", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptRecordWithLimits(candidate, c.limits); err != nil {
		return err
	}
	return nil
}

func (c *signAttemptCoordinator) acceptRecord(record SignAttemptRecord) error {
	if c == nil {
		return errors.New("nil sign attempt coordinator")
	}
	if !bytes.Equal(record.PresignID, c.handle) {
		return fmt.Errorf("%w: durable presign identity mismatch", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptRecordWithLimits(record, c.limits); err != nil {
		return err
	}
	if c.hasRecord && !c.attempt.SameAttempt(record) {
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
