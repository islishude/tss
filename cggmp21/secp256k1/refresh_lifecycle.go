package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

const refreshProtocolFailureReason = "cggmp21 refresh protocol failure"

func (s *RefreshSession) stageAndCommitRefreshFinal(ctx context.Context, prepared *preparedPaperFinalKeyShare) error {
	if s == nil || prepared == nil || prepared.share == nil {
		return errors.New("missing refreshed final key share")
	}
	if s.lifecycleFinal != nil && s.lifecycleFinal != prepared {
		return errors.New("conflicting pending refresh lifecycle result")
	}
	if s.lifecycleFinal == nil {
		s.lifecycleFinal = prepared
		prepared.committed = true
	}
	return s.commitPendingRefreshLifecycle(ctx)
}

func (s *RefreshSession) commitPendingRefreshLifecycle(ctx context.Context) error {
	if s.lifecycleFinished {
		return nil
	}
	if s.lifecycleStore == nil || s.lifecycleLease.Token == 0 || s.lifecycleFinal == nil || s.lifecycleFinal.share == nil {
		return errors.New("refresh lifecycle commit is not prepared")
	}
	finalShare := s.lifecycleFinal.share
	blob, err := finalShare.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return fmt.Errorf("encode refreshed key generation: %w", err)
	}
	defer clear(blob)
	metadata, ok := finalShare.PublicMetadata()
	if !ok || metadata.Epoch == nil {
		return errors.New("refreshed key generation has no public epoch metadata")
	}
	epochID, err := tssrun.NewEpochID(metadata.Epoch.EpochID)
	if err != nil {
		return fmt.Errorf("derive refreshed lifecycle epoch: %w", err)
	}
	target := tssrun.GenerationBinding{
		KeyID:         s.lifecycleSource.KeyID,
		KeyGeneration: s.lifecycleTargetGeneration,
		EpochID:       epochID,
	}
	if err := target.Validate(); err != nil || target.KeyGeneration == s.lifecycleSource.KeyGeneration || target.EpochID == s.lifecycleSource.EpochID {
		return errors.New("invalid refreshed lifecycle target binding")
	}
	storeCtx, cancel := durableStoreContext(ctx, s.lifecycleTimeout)
	fence, err := s.lifecycleStore.BeginCutoverFromLease(storeCtx, s.lifecycleLease, target)
	cancel()
	if err != nil {
		return fmt.Errorf("begin refreshed generation cutover: %w", err)
	}
	storeCtx, cancel = durableStoreContext(ctx, s.lifecycleTimeout)
	record, err := s.lifecycleStore.CommitCutover(storeCtx, fence, blob, metadata.PlanHash)
	cancel()
	if err != nil {
		return fmt.Errorf("commit refreshed generation cutover: %w", err)
	}
	if record.Binding != target || record.Status != tssrun.GenerationCurrent || !bytes.Equal(record.Blob, blob) {
		return fmt.Errorf("%w: refreshed generation commit mismatch", tssrun.ErrLifecycleCorrupt)
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
	s.log.Info(s.cfg.Ctx(), "refresh complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return nil
}

func (s *RefreshSession) markRefreshProtocolFailed(ctx context.Context) error {
	if s.lifecycleFinished {
		return nil
	}
	if s.lifecycleStore == nil || s.lifecycleLease.Token == 0 {
		return errors.New("refresh lifecycle failure marker is unavailable")
	}
	storeCtx, cancel := durableStoreContext(ctx, s.lifecycleTimeout)
	_, err := s.lifecycleStore.MarkProtocolRefreshFailed(storeCtx, s.lifecycleLease, refreshProtocolFailureReason)
	cancel()
	if err != nil {
		return fmt.Errorf("persist refresh protocol failure: %w", err)
	}
	s.lifecycleFinished = true
	return nil
}

// RetryLifecycleCommit retries a refresh success cutover or fail-closed
// protocol-failure marker after a transient durable-store error. If a local
// confirmation was withheld until the cutover committed, it is returned once.
func (s *RefreshSession) RetryLifecycleCommit(ctx context.Context) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil refresh session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lifecycleFinished {
		out := cloneLifecycleEnvelopes(s.lifecycleOutbox)
		clearLifecycleEnvelopes(s.lifecycleOutbox)
		s.lifecycleOutbox = nil
		return out, nil
	}
	var err error
	if s.refreshDisabled {
		err = s.markRefreshProtocolFailed(ctx)
	} else {
		err = s.commitPendingRefreshLifecycle(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := cloneLifecycleEnvelopes(s.lifecycleOutbox)
	clearLifecycleEnvelopes(s.lifecycleOutbox)
	s.lifecycleOutbox = nil
	return out, nil
}

func cloneLifecycleEnvelopes(in []tss.Envelope) []tss.Envelope {
	if len(in) == 0 {
		return nil
	}
	out := make([]tss.Envelope, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}

func clearLifecycleEnvelopes(in []tss.Envelope) {
	for i := range in {
		clear(in[i].Payload)
		clear(in[i].SenderSignature)
		in[i] = tss.Envelope{}
	}
}
