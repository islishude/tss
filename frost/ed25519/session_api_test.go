package ed25519

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

func TestFROSTHandleCancellationRejectsBeforeMutation(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2, Parties: tss.NewPartySet(1, 2), Self: 1, SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestSession(t, session)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := session.Handle(ctx, tss.InboundEnvelope{}); !errors.Is(err, context.Canceled) || len(out) != 0 {
		t.Fatalf("cancelled Handle out=%d err=%v", len(out), err)
	}
	if session.Status() != tssrun.SessionActive {
		t.Fatalf("cancelled Handle changed session status to %v", session.Status())
	}
}
