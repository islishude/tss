package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

func (s *ReshareSession) stageReshareFinal(prepared *preparedPaperFinalKeyShare) error {
	if s == nil || prepared == nil || prepared.share == nil || !s.isReceiver {
		return errors.New("missing reshare receiver final key share")
	}
	if s.lifecycleFinal != nil && s.lifecycleFinal != prepared {
		return errors.New("conflicting pending reshare lifecycle result")
	}
	if s.lifecycleRetirement != nil {
		return errors.New("reshare lifecycle role has conflicting terminal result")
	}
	if s.lifecycleFinal == nil {
		s.lifecycleFinal = prepared
		prepared.committed = true
	}
	return nil
}

func (s *ReshareSession) stageReshareRetirement(confirmation *KeygenConfirmation) error {
	if s == nil || confirmation == nil || s.isReceiver || !s.isDealer {
		return errors.New("invalid dealer-only reshare retirement")
	}
	if s.lifecycleFinal != nil {
		return errors.New("reshare lifecycle role has conflicting terminal result")
	}
	epochID, err := tssrun.NewEpochID(confirmation.EpochID)
	if err != nil {
		return fmt.Errorf("invalid reshare target epoch confirmation: %w", err)
	}
	target := tssrun.GenerationBinding{
		KeyID:         s.lifecycleSource.KeyID,
		KeyGeneration: s.lifecycleTargetGeneration,
		EpochID:       epochID,
	}
	if err := target.Validate(); err != nil || target.KeyGeneration == s.lifecycleSource.KeyGeneration || target.EpochID == s.lifecycleSource.EpochID {
		return errors.New("invalid dealer-only reshare retirement target")
	}
	if s.lifecycleRetirement != nil {
		if *s.lifecycleRetirement != target {
			return errors.New("conflicting dealer-only reshare retirement target")
		}
		return nil
	}
	s.lifecycleRetirement = &target
	return nil
}

func (s *ReshareSession) commitPendingReshareLifecycle(ctx context.Context) error {
	if s.lifecycleFinished {
		return nil
	}
	if s.lifecycleStore == nil || s.lifecycleLease.Token == 0 {
		return errors.New("reshare lifecycle store or lease is unavailable")
	}
	if s.lifecycleFinal != nil {
		return s.commitReshareReceiverGeneration(ctx)
	}
	if s.lifecycleRetirement != nil {
		storeCtx, cancel := durableStoreContext(ctx, s.lifecycleTimeout)
		err := s.lifecycleStore.CommitRetirementFromLease(storeCtx, s.lifecycleLease, *s.lifecycleRetirement)
		cancel()
		if err != nil {
			return fmt.Errorf("commit dealer-only reshare retirement: %w", err)
		}
		s.lifecycleFinished = true
		s.completed = true
		if s.oldKey != nil {
			s.oldKey.Destroy()
			s.oldKey = nil
		}
		s.log.Info(s.cfg.Ctx(), "dealer-only reshare retirement complete",
			"party_id", s.selfID,
			"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		)
		return nil
	}
	if s.aborted || s.figure7Failure != nil {
		storeCtx, cancel := durableStoreContext(ctx, s.lifecycleTimeout)
		err := s.lifecycleStore.FinishRunLease(storeCtx, s.lifecycleLease, tssrun.LeaseAborted)
		cancel()
		if err != nil {
			return fmt.Errorf("abort reshare run lease: %w", err)
		}
		s.lifecycleFinished = true
	}
	return nil
}

// commitReshareLifecycleEffects makes terminal protocol output visible only
// after the matching generation install, overlap cutover, dealer retirement,
// or abort is durable. A transient store failure retains the output for
// RetryLifecycleCommit.
func (s *ReshareSession) commitReshareLifecycleEffects(ctx context.Context, out []tss.Envelope) ([]tss.Envelope, error) {
	if s.lifecycleFinal == nil && s.lifecycleRetirement == nil && !s.aborted && s.figure7Failure == nil {
		return out, nil
	}
	if len(out) != 0 {
		clearLifecycleEnvelopes(s.lifecycleOutbox)
		s.lifecycleOutbox = cloneLifecycleEnvelopes(out)
	}
	if err := s.commitPendingReshareLifecycle(ctx); err != nil {
		return nil, err
	}
	clearLifecycleEnvelopes(s.lifecycleOutbox)
	s.lifecycleOutbox = nil
	return out, nil
}

func (s *ReshareSession) commitReshareReceiverGeneration(ctx context.Context) error {
	finalShare := s.lifecycleFinal.share
	blob, err := finalShare.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return fmt.Errorf("encode reshared key generation: %w", err)
	}
	defer clear(blob)
	metadata, ok := finalShare.PublicMetadata()
	if !ok || metadata.Epoch == nil {
		return errors.New("reshared key generation has no public epoch metadata")
	}
	epochID, err := tssrun.NewEpochID(metadata.Epoch.EpochID)
	if err != nil {
		return fmt.Errorf("derive reshared lifecycle epoch: %w", err)
	}
	target := tssrun.GenerationBinding{
		KeyID:         s.lifecycleSource.KeyID,
		KeyGeneration: s.lifecycleTargetGeneration,
		EpochID:       epochID,
	}
	if err := target.Validate(); err != nil || target.KeyGeneration == s.lifecycleSource.KeyGeneration || target.EpochID == s.lifecycleSource.EpochID {
		return errors.New("invalid reshared lifecycle target binding")
	}
	var record tssrun.GenerationRecord
	if s.isDealer {
		storeCtx, cancel := durableStoreContext(ctx, s.lifecycleTimeout)
		fence, beginErr := s.lifecycleStore.BeginCutoverFromLease(storeCtx, s.lifecycleLease, target)
		cancel()
		if beginErr != nil {
			return fmt.Errorf("begin overlap reshare cutover: %w", beginErr)
		}
		storeCtx, cancel = durableStoreContext(ctx, s.lifecycleTimeout)
		record, err = s.lifecycleStore.CommitCutover(storeCtx, fence, blob, metadata.PlanHash)
		cancel()
	} else {
		storeCtx, cancel := durableStoreContext(ctx, s.lifecycleTimeout)
		record, err = s.lifecycleStore.CommitInitialGenerationFromReshareLease(storeCtx, s.lifecycleLease, target, blob, metadata.PlanHash)
		cancel()
	}
	if err != nil {
		return fmt.Errorf("commit reshare receiver generation: %w", err)
	}
	if record.Binding != target || record.Status != tssrun.GenerationCurrent || !bytes.Equal(record.Blob, blob) {
		return fmt.Errorf("%w: reshared generation commit mismatch", tssrun.ErrLifecycleCorrupt)
	}
	pending := s.lifecycleFinal
	s.lifecycleFinal = nil
	if s.newShare != nil {
		s.newShare.Destroy()
	}
	s.newShare = pending.share
	pending.share = nil
	clear(pending.confirmationSetHash)
	pending.confirmationSetHash = nil
	s.lifecycleFinished = true
	s.completed = true
	if s.oldKey != nil {
		s.oldKey.Destroy()
		s.oldKey = nil
	}
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return nil
}

// RetryLifecycleCommit retries a reshare receiver install, overlap cutover,
// dealer retirement, or terminal abort after a transient durable-store error.
// Any protocol envelopes withheld with the transition are returned once.
func (s *ReshareSession) RetryLifecycleCommit(ctx context.Context) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.commitPendingReshareLifecycle(ctx); err != nil {
		return nil, err
	}
	out := cloneLifecycleEnvelopes(s.lifecycleOutbox)
	clearLifecycleEnvelopes(s.lifecycleOutbox)
	s.lifecycleOutbox = nil
	return out, nil
}
