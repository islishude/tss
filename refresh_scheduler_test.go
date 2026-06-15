package tss

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type refreshTestShare struct {
	name      string
	destroyed atomic.Bool
}

func (*refreshTestShare) Algorithm() Algorithm           { return AlgorithmFROSTEd25519 }
func (*refreshTestShare) PartyID() PartyID               { return 1 }
func (*refreshTestShare) PublicKeyBytes() []byte         { return []byte("public") }
func (*refreshTestShare) MarshalBinary() ([]byte, error) { return []byte("share"), nil }
func (s *refreshTestShare) Destroy()                     { s.destroyed.Store(true) }
func (s *refreshTestShare) wasDestroyed() bool           { return s.destroyed.Load() }
func refreshTestSessionID() SessionID                    { return SessionID{1} }
func refreshTestCommitOK(context.Context, *refreshTestShare, *refreshTestShare) error {
	return nil
}

type refreshTestAckVerifier struct{}

func (refreshTestAckVerifier) VerifyAck(PartyID, [32]byte, []byte) error { return nil }

type refreshTestTransport struct {
	mu           sync.Mutex
	deliveries   []string
	sendErr      error
	broadcastErr error
	receive      func(context.Context) (InboundEnvelope, error)
}

func (t *refreshTestTransport) Send(_ context.Context, env Envelope) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deliveries = append(t.deliveries, "send:"+string(env.PayloadType))
	return t.sendErr
}

func (t *refreshTestTransport) Broadcast(_ context.Context, env Envelope) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deliveries = append(t.deliveries, "broadcast:"+string(env.PayloadType))
	return t.broadcastErr
}

func (t *refreshTestTransport) Receive(ctx context.Context) (InboundEnvelope, error) {
	if t.receive != nil {
		return t.receive(ctx)
	}
	return InboundEnvelope{}, errors.New("unexpected receive")
}

func (t *refreshTestTransport) sent() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.deliveries...)
}

type refreshTestSession struct {
	mu        sync.Mutex
	refreshed *refreshTestShare
	complete  bool
	handle    func(InboundEnvelope) ([]Envelope, error)
	destroyed atomic.Bool
}

func (s *refreshTestSession) Handle(in InboundEnvelope) ([]Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil {
		return s.handle(in)
	}
	s.complete = true
	return nil, nil
}

func (s *refreshTestSession) KeyShare() (*refreshTestShare, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshed, s.complete
}

func (s *refreshTestSession) Destroy() {
	s.destroyed.Store(true)
}

type refreshTestRunner struct {
	start func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error)
}

func (r *refreshTestRunner) StartRefresh(ctx context.Context, current *refreshTestShare, config RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
	return r.start(ctx, current, config)
}

func refreshTestOptions(runner RefreshRunner[*refreshTestShare], transport Transport) RefreshSchedulerOptions[*refreshTestShare] {
	return RefreshSchedulerOptions[*refreshTestShare]{
		Interval:     time.Hour,
		Transport:    transport,
		Runner:       runner,
		ReplayCache:  NewInMemoryReplayCache(),
		AckVerifier:  refreshTestAckVerifier{},
		LoadKeyShare: func(context.Context) (*refreshTestShare, error) { return &refreshTestShare{name: "current"}, nil },
		SessionIDSource: func(context.Context, *refreshTestShare) (SessionID, error) {
			return refreshTestSessionID(), nil
		},
		CommitKeyShare: refreshTestCommitOK,
	}
}

func TestNewRefreshSchedulerRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	runner := &refreshTestRunner{start: func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
		return nil, nil, nil
	}}
	transport := &refreshTestTransport{}

	tests := []struct {
		name   string
		mutate func(*RefreshSchedulerOptions[*refreshTestShare])
		want   error
	}{
		{name: "interval", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.Interval = 0 }},
		{name: "transport", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.Transport = nil }},
		{name: "runner", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.Runner = nil }},
		{name: "replay cache", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.ReplayCache = nil }, want: ErrMissingReplayCache},
		{name: "ack verifier", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.AckVerifier = nil }, want: ErrMissingAckVerifier},
		{name: "load callback", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.LoadKeyShare = nil }},
		{name: "session callback", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.SessionIDSource = nil }},
		{name: "commit callback", mutate: func(o *RefreshSchedulerOptions[*refreshTestShare]) { o.CommitKeyShare = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			options := refreshTestOptions(runner, transport)
			tc.mutate(&options)
			_, err := NewRefreshScheduler(options)
			if err == nil {
				t.Fatal("expected constructor error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRefreshSchedulerRunOnceDrivesSessionAndPreservesEnvelopeOrder(t *testing.T) {
	t.Parallel()
	current := &refreshTestShare{name: "current"}
	refreshed := &refreshTestShare{name: "refreshed"}
	session := &refreshTestSession{refreshed: refreshed}
	session.handle = func(InboundEnvelope) ([]Envelope, error) {
		session.complete = true
		return []Envelope{
			{To: 3, PayloadType: "direct-response"},
			{PayloadType: "broadcast-response"},
		}, nil
	}
	transport := &refreshTestTransport{
		receive: func(context.Context) (InboundEnvelope, error) {
			return InboundEnvelope{}, nil
		},
	}
	var gotConfig RefreshRunConfig
	runner := &refreshTestRunner{start: func(_ context.Context, got *refreshTestShare, config RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
		if got != current {
			t.Fatalf("current share = %p, want %p", got, current)
		}
		gotConfig = config
		return session, []Envelope{
			{PayloadType: "broadcast-initial"},
			{To: 2, PayloadType: "direct-initial"},
		}, nil
	}}
	options := refreshTestOptions(runner, transport)
	options.LoadKeyShare = func(context.Context) (*refreshTestShare, error) { return current, nil }
	options.CommitKeyShare = func(_ context.Context, previous, next *refreshTestShare) error {
		if previous != current || next != refreshed {
			t.Fatalf("commit shares = (%p, %p), want (%p, %p)", previous, next, current, refreshed)
		}
		return nil
	}
	scheduler, err := NewRefreshScheduler(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantDeliveries := []string{
		"broadcast:broadcast-initial",
		"send:direct-initial",
		"send:direct-response",
		"broadcast:broadcast-response",
	}
	if got := transport.sent(); !reflect.DeepEqual(got, wantDeliveries) {
		t.Fatalf("deliveries = %v, want %v", got, wantDeliveries)
	}
	if gotConfig.SessionID != refreshTestSessionID() || gotConfig.ReplayCache != options.ReplayCache || gotConfig.AckVerifier != options.AckVerifier {
		t.Fatal("runner did not receive scheduler security configuration")
	}
	if !session.destroyed.Load() {
		t.Fatal("session was not destroyed")
	}
	if refreshed.wasDestroyed() {
		t.Fatal("successfully committed share was destroyed")
	}
}

func TestRefreshSchedulerCommitOwnership(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		commitErr     error
		wantDestroyed bool
	}{
		{name: "success"},
		{name: "definite failure", commitErr: errors.New("compare-and-swap failed"), wantDestroyed: true},
		{name: "unknown outcome", commitErr: fmt.Errorf("storage timeout: %w", ErrRefreshCommitOutcomeUnknown)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			refreshed := &refreshTestShare{name: "refreshed"}
			session := &refreshTestSession{refreshed: refreshed, complete: true}
			runner := &refreshTestRunner{start: func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
				return session, nil, nil
			}}
			options := refreshTestOptions(runner, &refreshTestTransport{})
			options.CommitKeyShare = func(context.Context, *refreshTestShare, *refreshTestShare) error {
				return tc.commitErr
			}
			scheduler, err := NewRefreshScheduler(options)
			if err != nil {
				t.Fatal(err)
			}
			err = scheduler.RunOnce(context.Background())
			if tc.commitErr == nil && err != nil {
				t.Fatal(err)
			}
			if tc.commitErr != nil && !errors.Is(err, tc.commitErr) {
				t.Fatalf("error = %v, want %v", err, tc.commitErr)
			}
			if got := refreshed.wasDestroyed(); got != tc.wantDestroyed {
				t.Fatalf("destroyed = %v, want %v", got, tc.wantDestroyed)
			}
			if !session.destroyed.Load() {
				t.Fatal("session was not destroyed")
			}
		})
	}
}

func TestRefreshSchedulerRejectsConcurrentRuns(t *testing.T) {
	t.Parallel()
	receiveStarted := make(chan struct{})
	var once sync.Once
	transport := &refreshTestTransport{
		receive: func(ctx context.Context) (InboundEnvelope, error) {
			once.Do(func() { close(receiveStarted) })
			<-ctx.Done()
			return InboundEnvelope{}, ctx.Err()
		},
	}
	session := &refreshTestSession{refreshed: &refreshTestShare{name: "unused"}}
	runner := &refreshTestRunner{start: func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
		return session, nil, nil
	}}
	scheduler, err := NewRefreshScheduler(refreshTestOptions(runner, transport))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- scheduler.RunOnce(ctx)
	}()
	<-receiveStarted
	if err := scheduler.RunOnce(context.Background()); !errors.Is(err, ErrRefreshSchedulerRunning) {
		t.Fatalf("concurrent error = %v, want %v", err, ErrRefreshSchedulerRunning)
	}
	cancel()
	if err := <-firstErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("first run error = %v, want context.Canceled", err)
	}
}

func TestRefreshSchedulerRunWaitsForIntervalAndStopsOnFailure(t *testing.T) {
	t.Parallel()
	loadCalled := make(chan struct{}, 1)
	runner := &refreshTestRunner{start: func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
		return nil, nil, errors.New("unexpected start")
	}}
	options := refreshTestOptions(runner, &refreshTestTransport{})
	options.Interval = 30 * time.Millisecond
	options.LoadKeyShare = func(context.Context) (*refreshTestShare, error) {
		loadCalled <- struct{}{}
		return nil, errors.New("load failed")
	}
	scheduler, err := NewRefreshScheduler(options)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- scheduler.Run(context.Background())
	}()
	select {
	case <-loadCalled:
		t.Fatal("refresh ran before the first interval")
	case <-time.After(5 * time.Millisecond):
	}
	select {
	case <-loadCalled:
	case <-time.After(time.Second):
		t.Fatal("refresh did not run after the interval")
	}
	err = <-errCh
	if err == nil || !strings.Contains(err.Error(), "load failed") {
		t.Fatalf("Run error = %v, want load failure", err)
	}
	select {
	case <-loadCalled:
		t.Fatal("scheduler continued after a failed run")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRefreshSchedulerPropagatesRunFailures(t *testing.T) {
	t.Parallel()
	testErr := errors.New("test failure")
	tests := []struct {
		name      string
		configure func(*refreshTestRunner, *refreshTestTransport, *refreshTestSession)
		want      string
	}{
		{
			name: "start",
			configure: func(r *refreshTestRunner, _ *refreshTestTransport, _ *refreshTestSession) {
				r.start = func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
					return nil, nil, testErr
				}
			},
			want: "start refresh",
		},
		{
			name: "broadcast",
			configure: func(r *refreshTestRunner, tr *refreshTestTransport, s *refreshTestSession) {
				tr.broadcastErr = testErr
				r.start = func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
					return s, []Envelope{{PayloadType: "broadcast"}}, nil
				}
			},
			want: "send initial refresh envelopes",
		},
		{
			name: "direct",
			configure: func(r *refreshTestRunner, tr *refreshTestTransport, s *refreshTestSession) {
				tr.sendErr = testErr
				r.start = func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
					return s, []Envelope{{To: 2, PayloadType: "direct"}}, nil
				}
			},
			want: "send initial refresh envelopes",
		},
		{
			name: "receive",
			configure: func(r *refreshTestRunner, tr *refreshTestTransport, s *refreshTestSession) {
				tr.receive = func(context.Context) (InboundEnvelope, error) { return InboundEnvelope{}, testErr }
				r.start = func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
					return s, nil, nil
				}
			},
			want: "receive refresh envelope",
		},
		{
			name: "handle",
			configure: func(r *refreshTestRunner, tr *refreshTestTransport, s *refreshTestSession) {
				tr.receive = func(context.Context) (InboundEnvelope, error) { return InboundEnvelope{}, nil }
				s.handle = func(InboundEnvelope) ([]Envelope, error) { return nil, testErr }
				r.start = func(context.Context, *refreshTestShare, RefreshRunConfig) (RefreshSession[*refreshTestShare], []Envelope, error) {
					return s, nil, nil
				}
			},
			want: "handle refresh envelope",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			transport := &refreshTestTransport{}
			session := &refreshTestSession{refreshed: &refreshTestShare{name: "unused"}}
			runner := &refreshTestRunner{}
			tc.configure(runner, transport, session)
			scheduler, err := NewRefreshScheduler(refreshTestOptions(runner, transport))
			if err != nil {
				t.Fatal(err)
			}
			err = scheduler.RunOnce(context.Background())
			if !errors.Is(err, testErr) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want wrapped test error containing %q", err, tc.want)
			}
		})
	}
}
