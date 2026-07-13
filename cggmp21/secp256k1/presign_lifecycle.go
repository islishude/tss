package secp256k1

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

const presignLifecycleSlotPrefix = "cggmp21-secp256k1-presign-"

// Presign consumption lifecycle:
//
//  1. A PresignSession atomically persists its completed Presign through the
//     acquired run lease before reporting success. The public session accessor
//     exposes only the resulting slot and public metadata. UnmarshalBinary
//     restores the available state only after complete cryptographic
//     revalidation of the normalized Figure 8 artifact.
//  2. StartSign replays persisted proof verification, constructs, and verifies a
//     candidate outbound envelope without
//     making it externally observable.
//  3. StartSign commits the immutable intent and envelope through
//     tssrun.LifecycleStore. That transaction destroys the available secret
//     blob and retains only public Figure 10 verification metadata.
//  4. MarshalBinary is a side-effect-free encoding of an available record.
//     The lifecycle store atomically claims that record with the exact attempt
//     and outbox; a bound record is never serializable again.
//  5. A committed or outcome-unknown attempt can only resume the same intent.
//
// The internal presign content ID commits to nonce secrets and is
// secret-tainted. LifecycleStore PresignID values use [PresignSlotID], which is
// derived only from the public, protocol-level PresignID and never from that
// secret-tainted content ID.

// PresignSlotID returns the only lifecycle-store slot permitted for a public
// CGGMP21 protocol PresignID. The protocol identifier must be exactly 32 bytes
// and non-zero; its canonical slot is the fixed prefix followed by lowercase
// hexadecimal.
func PresignSlotID(protocolPresignID []byte) (string, error) {
	if err := validateRequiredPlanID("protocol presign id", protocolPresignID); err != nil {
		return "", fmt.Errorf("%w: %w", tssrun.ErrInvalidLifecycleRecord, err)
	}
	return presignLifecycleSlotPrefix + hex.EncodeToString(protocolPresignID), nil
}

// PersistPresignFromLease atomically persists an available presign under its
// canonical public protocol PresignID slot and completes the exact presign run
// lease. Exact retries with the same lease and artifact are delegated to the
// lifecycle store's idempotent commit contract.
func PersistPresignFromLease(ctx context.Context, store tssrun.LifecycleStore, lease tssrun.RunLease, presign *Presign) (string, error) {
	return PersistPresignFromLeaseWithLimits(ctx, store, lease, presign, DefaultLimits())
}

// PersistPresignFromLeaseWithLimits is [PersistPresignFromLease] with explicit
// local validation and wire resource limits.
func PersistPresignFromLeaseWithLimits(ctx context.Context, store tssrun.LifecycleStore, lease tssrun.RunLease, presign *Presign, limits Limits) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: nil persistence context", tssrun.ErrInvalidLifecycleRecord)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if store == nil {
		return "", fmt.Errorf("%w: nil lifecycle store", tssrun.ErrInvalidLifecycleRecord)
	}
	if err := validatePresignPersistenceLease(lease); err != nil {
		return "", err
	}
	if presign == nil || presign.state == nil {
		return "", fmt.Errorf("%w: nil presign", tssrun.ErrInvalidLifecycleRecord)
	}
	if err := presign.ValidateWithLimits(limits); err != nil {
		return "", fmt.Errorf("%w: invalid presign artifact: %w", tssrun.ErrInvalidLifecycleRecord, err)
	}

	slot, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		return "", err
	}
	blob, err := presign.MarshalBinaryWithLimits(limits)
	if err != nil {
		return "", fmt.Errorf("%w: encode available presign: %w", tssrun.ErrInvalidLifecycleRecord, err)
	}
	defer clear(blob)
	metadata, err := presign.LifecycleMetadataWithLimits(limits)
	if err != nil {
		return "", fmt.Errorf("%w: encode presign public metadata: %w", tssrun.ErrInvalidLifecycleRecord, err)
	}
	defer clear(metadata)
	if err := validatePresignPersistenceArtifact(presign, lease.Binding, slot, metadata, limits); err != nil {
		return "", err
	}
	if err := store.CommitAvailablePresignFromLease(ctx, lease, slot, blob, metadata); err != nil {
		return "", err
	}
	return slot, nil
}

func validatePresignPersistenceLease(lease tssrun.RunLease) error {
	if lease.Token == 0 || lease.State != tssrun.RunLeaseActive || lease.Kind != tssrun.RunPresign || !lease.SessionID.Valid() {
		return fmt.Errorf("%w: invalid presign run lease", tssrun.ErrInvalidLifecycleRecord)
	}
	if err := lease.Binding.Validate(); err != nil {
		return err
	}
	return nil
}

func validatePresignPersistenceArtifact(presign *Presign, binding tssrun.GenerationBinding, slot string, metadata []byte, limits Limits) error {
	if presign == nil || presign.state == nil {
		return fmt.Errorf("%w: nil presign", tssrun.ErrInvalidLifecycleRecord)
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	publicContext, err := unmarshalSignAttemptPublicContext(metadata, limits)
	if err != nil {
		return fmt.Errorf("%w: invalid generated presign public metadata: %w", tssrun.ErrInvalidLifecycleRecord, err)
	}
	defer publicContext.destroy()
	if !signAttemptPublicContextMatchesPresign(publicContext, presign) {
		return fmt.Errorf("%w: presign public metadata does not match artifact", tssrun.ErrInvalidLifecycleRecord)
	}
	expectedSlot, err := PresignSlotID(publicContext.ProtocolPresignID)
	if err != nil {
		return err
	}
	if slot != expectedSlot {
		return fmt.Errorf("%w: non-canonical presign slot", tssrun.ErrInvalidLifecycleRecord)
	}
	if publicContext.KeyID != binding.KeyID || presign.state.Context.KeyID != binding.KeyID {
		return fmt.Errorf("%w: presign key binding mismatch", tssrun.ErrInvalidLifecycleRecord)
	}
	if !bytes.Equal(publicContext.EpochID, binding.EpochID[:]) || !bytes.Equal(presign.state.EpochID, binding.EpochID[:]) {
		return fmt.Errorf("%w: presign epoch binding mismatch", tssrun.ErrInvalidLifecycleRecord)
	}
	if !bytes.Equal(publicContext.ProtocolPresignID, presign.state.PresignID) {
		return fmt.Errorf("%w: presign protocol id mismatch", tssrun.ErrInvalidLifecycleRecord)
	}
	if !secpEqualPresignGamma(publicContext, presign) {
		return fmt.Errorf("%w: presign Gamma mismatch", tssrun.ErrInvalidLifecycleRecord)
	}
	return nil
}

func secpEqualPresignGamma(publicContext signAttemptPublicContext, presign *Presign) bool {
	return presign != nil && presign.state != nil && secp.Equal(publicContext.Gamma, presign.state.Gamma)
}

type presignAttemptState uint8

const (
	presignAttemptAvailable presignAttemptState = iota
	presignAttemptSnapshot
	presignAttemptBound
	presignAttemptDiscarded
)

type presignAttemptBinding struct {
	mu     sync.Mutex
	state  presignAttemptState
	intent []byte
}

//nolint:unparam // consumed preserves the snapshot-only constructor invariant for recovered records.
func newPresignAttemptBinding(consumed bool) *presignAttemptBinding {
	state := presignAttemptAvailable
	if consumed {
		state = presignAttemptSnapshot
	}
	return &presignAttemptBinding{state: state}
}

func (b *presignAttemptBinding) bind(intent []byte, recovered bool) bool {
	if b == nil || len(intent) == 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == presignAttemptBound {
		return bytes.Equal(b.intent, intent)
	}
	if b.state == presignAttemptDiscarded {
		return false
	}
	if b.state == presignAttemptSnapshot && !recovered {
		return false
	}
	b.state = presignAttemptBound
	b.intent = slices.Clone(intent)
	return true
}

func (b *presignAttemptBinding) discard() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != presignAttemptBound {
		b.state = presignAttemptDiscarded
		b.intent = nil
	}
}

func (b *presignAttemptBinding) available() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == presignAttemptAvailable
}

// DiscardLocalPresignHandle discards p's local in-process presign handle.
// It marks the local claim consumed, never releases an existing attempt binding,
// and is not a durable tombstone. Production discard paths should prefer
// [BurnPresign] when a tssrun.LifecycleStore is available.
func DiscardLocalPresignHandle(p *Presign) error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if p.state.Consumed.Bool == nil {
		return errors.New("presign claim state unavailable")
	}
	if p.state.attempt == nil {
		return errors.New("presign attempt state unavailable")
	}
	p.state.Consumed.Store(true)
	p.state.attempt.discard()
	return nil
}

// IsPresignConsumed reports whether the presign has been consumed.
func IsPresignConsumed(p *Presign) bool {
	return p == nil || p.state == nil || p.state.Consumed.Bool == nil || p.state.attempt == nil || p.state.Consumed.Load()
}

func bindPresignToAttempt(presign *Presign, intent []byte, recovered bool) bool {
	if presign == nil || presign.state == nil || presign.state.Consumed.Bool == nil || presign.state.attempt == nil {
		return false
	}
	if !presign.state.attempt.bind(intent, recovered) {
		return false
	}
	presign.state.Consumed.Store(true)
	return true
}
