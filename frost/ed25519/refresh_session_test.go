package ed25519

import (
	"context"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

func TestRefreshSessionFacadeDrivesProtocol(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	limits := testLimits()
	sessions := make(map[tss.PartyID]*RefreshSession, len(parties))
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		plan, err := NewRefreshPlan(RefreshPlanOption{
			OldKey: shares[id], SessionID: sessionID, Limits: &limits,
		})
		if err != nil {
			t.Fatal(err)
		}
		session, out, err := StartRefresh(
			shares[id],
			plan,
			tss.LocalConfig{Self: id},
			testFROSTGuard(id, parties, sessionID),
		)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	deliverReshareMessages(t, parties, queue, sessions)
	for _, id := range parties {
		if sessions[id].Status() != tssrun.SessionSucceeded {
			t.Fatalf("refresh session %d did not complete", id)
		}
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("refresh session %d did not expose a key share", id)
		}
		share.Destroy()
		closeTestSession(t, sessions[id])
	}
}

func TestRefreshSessionNilReceiverIsSafe(t *testing.T) {
	t.Parallel()
	var session *RefreshSession
	if session.Guard() != nil || session.Status() != tssrun.SessionClosed {
		t.Fatal("nil refresh session exposed state")
	}
	if share, ok := session.KeyShare(); ok || share != nil {
		t.Fatal("nil refresh session exposed a key share")
	}
	if _, err := session.Handle(context.Background(), tss.InboundEnvelope{}); err == nil {
		t.Fatal("nil refresh session accepted an envelope")
	}
	closeTestSession(t, session)
}
