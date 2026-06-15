package ed25519

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/islishude/tss"
)

type frostRefreshRunnerTransport struct {
	sent int
}

func (t *frostRefreshRunnerTransport) Send(context.Context, tss.Envelope) error {
	t.sent++
	return nil
}

func (t *frostRefreshRunnerTransport) Broadcast(context.Context, tss.Envelope) error {
	t.sent++
	return nil
}

func (*frostRefreshRunnerTransport) Receive(context.Context) (tss.InboundEnvelope, error) {
	return tss.InboundEnvelope{}, errors.New("unexpected receive")
}

func TestFROSTRefreshRunnerCompletesThroughSharedScheduler(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 1, 1)
	current := shares[1]
	oldPublicKey := current.PublicKeyBytes()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	limits := testLimits()
	transport := &frostRefreshRunnerTransport{}
	var committed *KeyShare
	scheduler, err := tss.NewRefreshScheduler(tss.RefreshSchedulerOptions[*KeyShare]{
		Interval:    time.Hour,
		Transport:   transport,
		Runner:      NewRefreshRunner(RefreshRunnerOptions{Limits: &limits}),
		ReplayCache: tss.NewInMemoryReplayCache(),
		AckVerifier: tss.NewInMemoryAckVerifier(func(tss.PartyID, [32]byte, []byte) error {
			return nil
		}),
		LoadKeyShare: func(context.Context) (*KeyShare, error) {
			return current, nil
		},
		SessionIDSource: func(context.Context, *KeyShare) (tss.SessionID, error) {
			return sessionID, nil
		},
		CommitKeyShare: func(_ context.Context, previous, refreshed *KeyShare) error {
			if previous != current {
				t.Fatal("scheduler did not pass the loaded share to commit")
			}
			committed = refreshed
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if committed == nil {
		t.Fatal("refresh did not commit a key share")
	}
	if !bytes.Equal(committed.PublicKeyBytes(), oldPublicKey) {
		t.Fatal("refresh changed the group public key")
	}
	if transport.sent == 0 {
		t.Fatal("refresh did not send its initial envelope")
	}
}
