package tss_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss"
)

type exampleRefreshShare struct {
	generation int
}

func (*exampleRefreshShare) Algorithm() tss.Algorithm       { return tss.AlgorithmFROSTEd25519 }
func (*exampleRefreshShare) PartyID() tss.PartyID           { return 1 }
func (*exampleRefreshShare) PublicKeyBytes() []byte         { return []byte("group-public-key") }
func (*exampleRefreshShare) MarshalBinary() ([]byte, error) { return []byte("example-share"), nil }
func (*exampleRefreshShare) Destroy()                       {}

type exampleRefreshRunner struct{}

func (exampleRefreshRunner) StartRefresh(context.Context, *exampleRefreshShare, tss.RefreshRunConfig) (tss.RefreshSession[*exampleRefreshShare], []tss.Envelope, error) {
	return exampleRefreshSession{refreshed: &exampleRefreshShare{generation: 2}}, nil, nil
}

type exampleRefreshSession struct {
	refreshed *exampleRefreshShare
}

func (exampleRefreshSession) Handle(tss.InboundEnvelope) ([]tss.Envelope, error) {
	return nil, errors.New("example refresh is already complete")
}

func (s exampleRefreshSession) KeyShare() (*exampleRefreshShare, bool) {
	return s.refreshed, true
}

func (exampleRefreshSession) Destroy() {}

type exampleRefreshTransport struct{}

func (exampleRefreshTransport) Send(context.Context, tss.Envelope) error      { return nil }
func (exampleRefreshTransport) Broadcast(context.Context, tss.Envelope) error { return nil }
func (exampleRefreshTransport) Receive(context.Context) (tss.InboundEnvelope, error) {
	return tss.InboundEnvelope{}, errors.New("example refresh is already complete")
}

type exampleAckVerifier struct{}

func (exampleAckVerifier) VerifyAck(tss.PartyID, [32]byte, []byte) error { return nil }

// ExampleRefreshScheduler_RunOnce demonstrates an operationally triggered
// refresh with an atomic compare-and-swap commit callback.
func ExampleRefreshScheduler_RunOnce() {
	current := &exampleRefreshShare{generation: 1}
	scheduler, err := tss.NewRefreshScheduler(tss.RefreshSchedulerOptions[*exampleRefreshShare]{
		Interval:    24 * time.Hour,
		Transport:   exampleRefreshTransport{},
		Runner:      exampleRefreshRunner{},
		ReplayCache: tss.NewInMemoryReplayCache(),
		AckVerifier: exampleAckVerifier{},
		LoadKeyShare: func(context.Context) (*exampleRefreshShare, error) {
			return current, nil
		},
		SessionIDSource: func(context.Context, *exampleRefreshShare) (tss.SessionID, error) {
			return tss.SessionID{1}, nil
		},
		CommitKeyShare: func(_ context.Context, previous, refreshed *exampleRefreshShare) error {
			if current != previous {
				return errors.New("key share changed concurrently")
			}
			current = refreshed
			return nil
		},
	})
	if err != nil {
		panic(err)
	}
	if err := scheduler.RunOnce(context.Background()); err != nil {
		panic(err)
	}
	fmt.Println(current.generation)
	// Output:
	// 2
}
