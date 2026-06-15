package secp256k1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/islishude/tss"
)

type testRefreshTransport struct {
	send func([]tss.Envelope) error
	recv func(ctx context.Context) (tss.InboundEnvelope, error)
}

func (t *testRefreshTransport) Send(envs []tss.Envelope) error { return t.send(envs) }
func (t *testRefreshTransport) Recv(ctx context.Context) (tss.InboundEnvelope, error) {
	return t.recv(ctx)
}

func testRefreshSchedulerSecurityOptions(t *testing.T) (func(context.Context, *KeyShare) (tss.SessionID, error), tss.BroadcastAckVerifier) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, *KeyShare) (tss.SessionID, error) {
		return sessionID, nil
	}, tss.NewInMemoryAckVerifier(nil)
}

func TestRefreshSchedulerInvalidOptions(t *testing.T) {
	t.Parallel()
	_, err := NewRefreshScheduler(RefreshSchedulerOptions{})
	if err == nil {
		t.Fatal("expected error for zero interval")
	}
	_, err = NewRefreshScheduler(RefreshSchedulerOptions{
		Interval:          time.Minute,
		GetKeyShare:       func() (*KeyShare, error) { return nil, errors.New("test") },
		OnRefreshComplete: func(*KeyShare) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error for nil transport")
	}
	_, err = NewRefreshScheduler(RefreshSchedulerOptions{
		Interval:  time.Minute,
		Transport: &testRefreshTransport{},
	})
	if err == nil {
		t.Fatal("expected error for nil GetKeyShare")
	}
}

func TestRefreshSchedulerStopWithoutStart(t *testing.T) {
	t.Parallel()
	sessionIDSource, ackVerifier := testRefreshSchedulerSecurityOptions(t)
	sched, err := NewRefreshScheduler(RefreshSchedulerOptions{
		Interval:          time.Minute,
		Transport:         &testRefreshTransport{},
		SessionIDSource:   sessionIDSource,
		AckVerifier:       ackVerifier,
		GetKeyShare:       func() (*KeyShare, error) { return nil, errors.New("test") },
		OnRefreshComplete: func(*KeyShare) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Stop must not panic even if Start was never called.
	sched.Stop()
}

func TestRefreshSchedulerContextCancel(t *testing.T) {
	t.Parallel()
	sessionIDSource, ackVerifier := testRefreshSchedulerSecurityOptions(t)
	sched, err := NewRefreshScheduler(RefreshSchedulerOptions{
		Interval:          time.Hour,
		Transport:         &testRefreshTransport{},
		SessionIDSource:   sessionIDSource,
		AckVerifier:       ackVerifier,
		GetKeyShare:       func() (*KeyShare, error) { return nil, errors.New(("test")) },
		OnRefreshComplete: func(*KeyShare) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = sched.Start(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
