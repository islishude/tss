package secp256k1

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/islishude/tss"
)

// RefreshTransport abstracts the network layer for proactive refresh exchanges.
// The caller provides message delivery; the scheduler drives the protocol.
type RefreshTransport interface {
	Send(envs []tss.Envelope) error
	Recv(ctx context.Context) (tss.Envelope, error)
}

// RefreshSchedulerOptions configures the proactive refresh scheduler.
type RefreshSchedulerOptions struct {
	// Interval is the time between successive refresh protocol runs.
	Interval time.Duration
	// Transport delivers refresh envelopes between participants.
	Transport RefreshTransport
	// SessionIDSource returns the externally coordinated session ID for the
	// next refresh run. All participants in one run must receive the same ID.
	SessionIDSource func(ctx context.Context, current *KeyShare) (tss.SessionID, error)
	// AckVerifier verifies broadcast consistency certificates for refresh
	// broadcast envelopes.
	AckVerifier tss.BroadcastAckVerifier
	// ReplayCache stores seen refresh envelopes. If nil, an in-memory cache is
	// created per scheduler run.
	ReplayCache tss.ReplayCache
	// GetKeyShare returns the current key share. It is called synchronously
	// before each refresh run and must be safe for concurrent access.
	GetKeyShare func() (*KeyShare, error)
	// OnRefreshComplete is called with the new key share after a successful
	// refresh. The caller must persist the new share atomically before
	// returning.
	OnRefreshComplete func(newShare *KeyShare) error
}

// RefreshScheduler runs proactive CGGMP21 key-share refresh on a periodic
// interval. Each refresh rotates Paillier keys and updates the local secret
// share while preserving the group public key and chain code.
type RefreshScheduler struct {
	opts   RefreshSchedulerOptions
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewRefreshScheduler creates a RefreshScheduler.
func NewRefreshScheduler(opts RefreshSchedulerOptions) (*RefreshScheduler, error) {
	if opts.Interval <= 0 {
		return nil, errors.New("refresh interval must be positive")
	}
	if opts.Transport == nil {
		return nil, errors.New("refresh transport must not be nil")
	}
	if opts.SessionIDSource == nil {
		return nil, errors.New("refresh session id source must not be nil")
	}
	if opts.AckVerifier == nil {
		return nil, tss.ErrMissingAckVerifier
	}
	if opts.GetKeyShare == nil {
		return nil, errors.New("GetKeyShare callback must not be nil")
	}
	if opts.OnRefreshComplete == nil {
		return nil, errors.New("OnRefreshComplete callback must not be nil")
	}
	return &RefreshScheduler{
		opts:   opts,
		stopCh: make(chan struct{}),
	}, nil
}

// Start begins the periodic refresh loop. It blocks until ctx is cancelled
// or Stop is called. The first refresh runs after one interval.
func (s *RefreshScheduler) Start(ctx context.Context) error {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(s.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopCh:
			return nil
		case <-ticker.C:
			if err := s.runRefresh(ctx); err != nil {
				return fmt.Errorf("refresh scheduler: %w", err)
			}
		}
	}
}

// Stop signals the scheduler to stop after the current refresh completes.
// It blocks until the refresh loop has exited.
func (s *RefreshScheduler) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
}

func (s *RefreshScheduler) runRefresh(ctx context.Context) error {
	keyShare, err := s.opts.GetKeyShare()
	if err != nil {
		return fmt.Errorf("get key share: %w", err)
	}
	sessionID, err := s.opts.SessionIDSource(ctx, keyShare)
	if err != nil {
		return fmt.Errorf("refresh session id: %w", err)
	}
	cache := s.opts.ReplayCache
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	guard, err := (tss.GuardConfig{
		Self:        keyShare.state.party,
		Parties:     tss.PartySet(keyShare.state.parties),
		Protocol:    protocol,
		SessionID:   sessionID,
		Policies:    CGGMP21Policies(),
		Cache:       cache,
		AckVerifier: s.opts.AckVerifier,
	}).BuildGuard()
	if err != nil {
		return fmt.Errorf("new guard: %w", err)
	}
	plan, err := NewRefreshPlan(keyShare, sessionID)
	if err != nil {
		return fmt.Errorf("build refresh plan: %w", err)
	}
	session, out, err := StartRefresh(keyShare, plan, tss.LocalConfig{Self: keyShare.state.party, Context: ctx}, guard)
	if err != nil {
		return fmt.Errorf("start refresh: %w", err)
	}
	defer session.Destroy()
	if err := s.opts.Transport.Send(out); err != nil {
		return fmt.Errorf("send refresh envelopes: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		newShare, ok := session.KeyShare()
		if ok {
			if err := s.opts.OnRefreshComplete(newShare); err != nil {
				return fmt.Errorf("on refresh complete: %w", err)
			}
			return nil
		}
		env, err := s.opts.Transport.Recv(ctx)
		if err != nil {
			return fmt.Errorf("recv refresh envelope: %w", err)
		}
		out, err := session.HandleRefreshMessage(env)
		if err != nil {
			return fmt.Errorf("handle refresh message: %w", err)
		}
		if err := s.opts.Transport.Send(out); err != nil {
			return fmt.Errorf("send refresh response: %w", err)
		}
	}
}
