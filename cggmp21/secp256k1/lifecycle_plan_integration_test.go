//go:build integration || vectorgen

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21KeygenMixedPlanHashRejectsWithoutStateMutation(t *testing.T) {
	sessionID := cggmpPlanTestSession(0x61)
	parties := tss.NewPartySet(1, 2, 3)
	plan1Security := testSecurityParams()
	plan1, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2, SecurityParams: &plan1Security})
	if err != nil {
		t.Fatal(err)
	}
	plan2Security := testSecurityParams()
	plan2Security.MinPaillierBits = 1024
	plan2, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2, SecurityParams: &plan2Security})
	if err != nil {
		t.Fatal(err)
	}

	s1, _, err := StartKeygen(plan1, tss.LocalConfig{Self: 1}, testCGGMP21Guard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(plan2, tss.LocalConfig{Self: 2}, testCGGMP21Guard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}

	env, ok := findCGGMPEnvelopeTo(out2, 1, payloadKeygenShare)
	if !ok {
		t.Fatal("missing keygen share from party 2 to party 1")
	}
	beforeShares := len(s1.shares)
	beforeCommits := len(s1.commits)
	beforePaillier := len(s1.paillierPubs)
	out, err := s1.HandleKeygenMessage(testutil.DeliverEnvelope(env))
	if len(out) != 0 {
		t.Fatalf("plan mismatch emitted %d envelopes", len(out))
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if len(s1.shares) != beforeShares || len(s1.commits) != beforeCommits || len(s1.paillierPubs) != beforePaillier {
		t.Fatal("plan mismatch mutated keygen state")
	}
	if s1.aborted {
		t.Fatal("plan mismatch aborted keygen session")
	}
}

func findCGGMPEnvelopeTo(envelopes []tss.Envelope, to tss.PartyID, payloadType tss.PayloadType) (tss.Envelope, bool) {
	for _, env := range envelopes {
		if env.To == to && env.PayloadType == payloadType {
			return env, true
		}
	}
	return tss.Envelope{}, false
}
