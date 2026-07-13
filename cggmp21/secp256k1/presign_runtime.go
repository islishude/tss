package secp256k1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

// PresignRuntime contains this process's local execution and durability
// dependencies for one CGGMP21 presign run. These values are not shared intent
// and are not included in the presign plan digest.
//
// StartPresign loads the exact current key generation named by Binding from
// LifecycleStore. It never accepts a caller-supplied secret KeyShare.
type PresignRuntime struct {
	Local               tss.LocalConfig
	Guard               *tss.EnvelopeGuard
	LifecycleStore      tssrun.LifecycleStore
	Binding             tssrun.GenerationBinding
	DurableStoreTimeout time.Duration
}

// PersistedPresign is an opaque, public-only descriptor for a presign that is
// already available in a LifecycleStore. Secret nonce shares are never exposed
// through this value.
type PersistedPresign struct {
	slot     string
	metadata PresignPublicMetadata
}

// SlotID returns the canonical LifecycleStore presign slot.
func (p PersistedPresign) SlotID() string { return p.slot }

// PublicMetadata returns an independently owned public metadata snapshot.
func (p PersistedPresign) PublicMetadata() PresignPublicMetadata {
	return p.metadata.Clone()
}

func newPersistedPresign(slot string, metadata PresignPublicMetadata) PersistedPresign {
	return PersistedPresign{slot: slot, metadata: metadata.Clone()}
}

func (p *PersistedPresign) destroy() {
	if p == nil {
		return
	}
	p.metadata = PresignPublicMetadata{}
	p.slot = ""
}

func (s *PresignSession) abortPresignRun(cause error) error {
	if s == nil {
		return cause
	}
	s.abort()
	if s.leaseFinished || s.lifecycleStore == nil || s.lifecycleLease.Token == 0 {
		return cause
	}
	storeCtx, cancel := durableStoreContext(s.config.Ctx(), s.lifecycleTimeout)
	finishErr := s.lifecycleStore.FinishRunLease(storeCtx, s.lifecycleLease, tssrun.LeaseAborted)
	cancel()
	if finishErr != nil {
		return errors.Join(cause, fmt.Errorf("abort presign run lease: %w", finishErr))
	}
	s.leaseFinished = true
	return cause
}

func abortPresignLeaseBestEffort(ctx context.Context, store tssrun.LifecycleStore, lease tssrun.RunLease, timeout time.Duration) {
	if store == nil || lease.Token == 0 || lease.State != tssrun.RunLeaseActive {
		return
	}
	storeCtx, cancel := durableStoreContext(ctx, timeout)
	_ = store.FinishRunLease(storeCtx, lease, tssrun.LeaseAborted)
	cancel()
}
