package tss

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// RefreshRunConfig carries the security configuration for one refresh run.
type RefreshRunConfig struct {
	SessionID        SessionID
	ReplayCache      ReplayCache
	AckVerifier      BroadcastAckVerifier
	EnvelopeSigner   EnvelopeSigner
	EnvelopeVerifier EnvelopeSignatureVerifier
}

// RefreshSession is the protocol-independent surface needed to drive one
// externally committed key-share refresh session. Implementations must not
// install or otherwise durably commit their candidate share themselves.
type RefreshSession[K KeyShare] interface {
	// Handle validates and applies one inbound refresh envelope.
	Handle(InboundEnvelope) ([]Envelope, error)
	// KeyShare returns an independent caller-owned share after completion. The
	// returned share must remain valid after Destroy is called on the session.
	KeyShare() (K, bool)
	// Destroy clears secret material retained by the session.
	Destroy()
}

// RefreshRunner adapts an algorithm-specific, externally committed refresh
// protocol to the shared scheduler. Protocols whose session owns a durable
// lifecycle lease or cutover transaction must be driven through their native
// lifecycle API instead.
type RefreshRunner[K KeyShare] interface {
	// Protocol returns the protocol whose replay state the runner uses.
	Protocol() ProtocolID
	// StartRefresh constructs one algorithm-specific refresh session.
	StartRefresh(context.Context, K, RefreshRunConfig) (RefreshSession[K], []Envelope, error)
}

// RefreshSchedulerOptions configures periodic proactive key-share refresh.
type RefreshSchedulerOptions[K KeyShare] struct {
	// Interval is the delay before the first refresh and between successful runs.
	Interval time.Duration
	// Transport delivers protocol envelopes with authenticated receive metadata.
	Transport Transport
	// Runner starts algorithm-specific refresh sessions.
	Runner RefreshRunner[K]
	// ReplayCache stores seen refresh envelopes across scheduler runs.
	ReplayCache ReplayCache
	// AckVerifier verifies broadcast consistency certificates.
	AckVerifier BroadcastAckVerifier
	// EnvelopeSigner authenticates local direct refresh envelopes.
	EnvelopeSigner EnvelopeSigner
	// EnvelopeVerifier authenticates direct refresh envelopes from peers.
	EnvelopeVerifier EnvelopeSignatureVerifier
	// LoadKeyShare returns the current key share at the start of each run.
	LoadKeyShare func(context.Context) (K, error)
	// SessionIDSource returns the externally coordinated unique session ID for
	// the next run. Every participant in one run must receive the same ID.
	SessionIDSource func(context.Context, K) (SessionID, error)
	// ClaimSessionID durably and atomically records first use of a session ID.
	// A claimed ID remains unavailable even if this refresh later fails.
	ClaimSessionID func(context.Context, SessionID) error
	// CommitKeyShare is the sole durable commit boundary for a scheduler run. It
	// atomically persists and installs refreshed if previous is still current.
	// The Runner and RefreshSession must not perform this commit themselves. A
	// nil result transfers ownership of refreshed to the callback. On a normal
	// error the scheduler destroys refreshed. If the error wraps
	// ErrRefreshCommitOutcomeUnknown, the callback retains ownership because the
	// durable commit may have succeeded.
	CommitKeyShare func(context.Context, K, K) error
}

// RefreshScheduler periodically drives proactive refresh protocols that use an
// external compare-and-swap commit callback. It does not support protocols
// whose session owns its lifecycle cutover. A scheduler permits only one active
// Run or RunOnce call at a time.
type RefreshScheduler[K KeyShare] struct {
	opts RefreshSchedulerOptions[K]

	mu      sync.Mutex
	running bool
}

// NewRefreshScheduler constructs a proactive refresh scheduler.
func NewRefreshScheduler[K KeyShare](opts RefreshSchedulerOptions[K]) (*RefreshScheduler[K], error) {
	switch {
	case opts.Interval <= 0:
		return nil, errors.New("refresh interval must be positive")
	case isNilRefreshValue(opts.Transport):
		return nil, errors.New("refresh transport must not be nil")
	case isNilRefreshValue(opts.Runner):
		return nil, errors.New("refresh runner must not be nil")
	case opts.Runner.Protocol() == "":
		return nil, errors.New("refresh runner protocol must not be empty")
	case isNilRefreshValue(opts.ReplayCache):
		return nil, ErrMissingReplayCache
	case isNilRefreshValue(opts.AckVerifier):
		return nil, ErrMissingAckVerifier
	case opts.LoadKeyShare == nil:
		return nil, errors.New("LoadKeyShare callback must not be nil")
	case opts.SessionIDSource == nil:
		return nil, errors.New("SessionIDSource callback must not be nil")
	case opts.ClaimSessionID == nil:
		return nil, errors.New("ClaimSessionID callback must not be nil")
	case opts.CommitKeyShare == nil:
		return nil, errors.New("CommitKeyShare callback must not be nil")
	}
	return &RefreshScheduler[K]{opts: opts}, nil
}

// Run executes refresh periodically until ctx is cancelled or a run fails. The
// first refresh starts after one interval.
func (s *RefreshScheduler[K]) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("refresh context must not be nil")
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()

	timer := time.NewTimer(s.opts.Interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := s.runOnce(ctx); err != nil {
				return fmt.Errorf("refresh scheduler: %w", err)
			}
			timer.Reset(s.opts.Interval)
		}
	}
}

// RunOnce immediately executes one refresh run.
func (s *RefreshScheduler[K]) RunOnce(ctx context.Context) error {
	if ctx == nil {
		return errors.New("refresh context must not be nil")
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.runOnce(ctx)
}

func (s *RefreshScheduler[K]) begin() error {
	if s == nil {
		return errors.New("nil refresh scheduler")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return ErrRefreshSchedulerRunning
	}
	s.running = true
	return nil
}

func (s *RefreshScheduler[K]) end() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

func (s *RefreshScheduler[K]) runOnce(ctx context.Context) (runErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := s.opts.LoadKeyShare(ctx)
	if err != nil {
		return fmt.Errorf("load key share: %w", err)
	}
	if isNilRefreshValue(current) {
		return errors.New("load key share returned nil")
	}
	sessionID, err := s.opts.SessionIDSource(ctx, current)
	if err != nil {
		return fmt.Errorf("refresh session id: %w", err)
	}
	if !sessionID.Valid() {
		return fmt.Errorf("refresh session id: %w", ErrInvalidSessionID)
	}
	if err := s.opts.ClaimSessionID(ctx, sessionID); err != nil {
		return fmt.Errorf("claim refresh session id: %w", err)
	}
	protocol := s.opts.Runner.Protocol()
	defer func() {
		if err := s.opts.ReplayCache.RetireSession(protocol, sessionID); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("retire refresh replay state: %w", err))
		}
	}()
	session, out, err := s.opts.Runner.StartRefresh(ctx, current, RefreshRunConfig{
		SessionID:        sessionID,
		ReplayCache:      s.opts.ReplayCache,
		AckVerifier:      s.opts.AckVerifier,
		EnvelopeSigner:   s.opts.EnvelopeSigner,
		EnvelopeVerifier: s.opts.EnvelopeVerifier,
	})
	if err != nil {
		return fmt.Errorf("start refresh: %w", err)
	}
	if isNilRefreshValue(session) {
		return errors.New("start refresh returned nil session")
	}
	defer session.Destroy()

	if err := sendRefreshEnvelopes(ctx, s.opts.Transport, out); err != nil {
		return fmt.Errorf("send initial refresh envelopes: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		refreshed, ok := session.KeyShare()
		if ok {
			if isNilRefreshValue(refreshed) {
				return errors.New("refresh session completed with nil key share")
			}
			if err := s.opts.CommitKeyShare(ctx, current, refreshed); err != nil {
				if !errors.Is(err, ErrRefreshCommitOutcomeUnknown) {
					refreshed.Destroy()
				}
				return fmt.Errorf("commit refreshed key share: %w", err)
			}
			return nil
		}
		in, err := s.opts.Transport.Receive(ctx)
		if err != nil {
			return fmt.Errorf("receive refresh envelope: %w", err)
		}
		out, err := session.Handle(in)
		if err != nil {
			return fmt.Errorf("handle refresh envelope: %w", err)
		}
		if err := sendRefreshEnvelopes(ctx, s.opts.Transport, out); err != nil {
			return fmt.Errorf("send refresh envelopes: %w", err)
		}
	}
}

func sendRefreshEnvelopes(ctx context.Context, transport Transport, envs []Envelope) error {
	for i, env := range envs {
		var err error
		if env.To == BroadcastPartyId {
			err = transport.Broadcast(ctx, env)
		} else {
			err = transport.Send(ctx, env)
		}
		if err != nil {
			return fmt.Errorf("envelope %d: %w", i, err)
		}
	}
	return nil
}

func isNilRefreshValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
