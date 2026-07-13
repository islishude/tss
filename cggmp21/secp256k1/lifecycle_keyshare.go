package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss/tssrun"
)

// loadLifecycleKeyShare loads, canonically decodes, and fully revalidates the
// exact current generation named by binding. The returned share is owned by
// the caller and must be destroyed.
func loadLifecycleKeyShare(ctx context.Context, store tssrun.LifecycleStore, binding tssrun.GenerationBinding, limits Limits, timeout time.Duration) (*KeyShare, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil lifecycle store", tssrun.ErrInvalidLifecycleRecord)
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	storeCtx, cancel := durableStoreContext(ctx, timeout)
	record, err := store.LoadCurrentGeneration(storeCtx, binding.KeyID)
	cancel()
	if err != nil {
		return nil, err
	}
	defer clear(record.Blob)
	defer clear(record.Metadata)
	if record.Binding != binding || record.Status != tssrun.GenerationCurrent {
		return nil, fmt.Errorf("%w: loaded generation does not match requested binding", tssrun.ErrLifecycleCorrupt)
	}
	key := new(KeyShare)
	if err := key.UnmarshalBinaryWithLimits(record.Blob, limits); err != nil {
		key.Destroy()
		return nil, fmt.Errorf("%w: decode current key generation: %w", tssrun.ErrLifecycleCorrupt, err)
	}
	canonical, err := key.MarshalBinaryWithLimits(limits)
	if err != nil {
		key.Destroy()
		return nil, fmt.Errorf("%w: revalidate current key generation: %w", tssrun.ErrLifecycleCorrupt, err)
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, record.Blob) {
		key.Destroy()
		return nil, fmt.Errorf("%w: non-canonical current key generation", tssrun.ErrLifecycleCorrupt)
	}
	if err := key.requireMPCMaterial(limits); err != nil {
		key.Destroy()
		return nil, fmt.Errorf("%w: invalid current key generation: %w", tssrun.ErrLifecycleCorrupt, err)
	}
	if key.state.Epoch == nil || !bytes.Equal(key.state.Epoch.EpochID, binding.EpochID[:]) {
		key.Destroy()
		return nil, fmt.Errorf("%w: current key generation epoch does not match binding", tssrun.ErrLifecycleCorrupt)
	}
	return key, nil
}

func finishLifecycleLease(ctx context.Context, store tssrun.LifecycleStore, lease tssrun.RunLease, timeout time.Duration, cause error) error {
	storeCtx, cancel := durableStoreContext(ctx, timeout)
	defer cancel()
	if err := store.FinishRunLease(storeCtx, lease, tssrun.LeaseAborted); err != nil {
		return errors.Join(cause, fmt.Errorf("abort uncommitted lifecycle run lease: %w", err))
	}
	return cause
}
