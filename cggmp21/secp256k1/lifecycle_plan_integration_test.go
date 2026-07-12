//go:build integration

package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21RefreshMixedSourceGenerationsRejectsWithoutStateMutation(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	original := CachedKeygenShares(t, 2, 2)
	firstRefreshID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	firstSessions := runRefresh(t, original, parties, firstRefreshID)
	refreshed := make(map[tss.PartyID]*KeyShare, len(parties))
	for _, id := range parties {
		share, ok := firstSessions[id].KeyShare()
		if !ok {
			t.Fatalf("first refresh did not complete for party %d", id)
		}
		refreshed[id] = share
		defer share.Destroy()
	}

	originalMeta := mustKeyShareMetadata(t, original[2])
	refreshedMeta := mustKeyShareMetadata(t, refreshed[1])
	if !bytes.Equal(originalMeta.PublicKey, refreshedMeta.PublicKey) || !bytes.Equal(originalMeta.ChainCode, refreshedMeta.ChainCode) {
		t.Fatal("mixed-generation fixture did not preserve public key metadata")
	}
	if bytes.Equal(originalMeta.KeygenTranscriptHash, refreshedMeta.KeygenTranscriptHash) {
		t.Fatal("mixed-generation fixture has identical source transcript hashes")
	}

	mixedRefreshID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	newGenerationSession, _, err := startCGGMP21Refresh(refreshed[1], tss.ThresholdConfig{
		Threshold: 2, Parties: parties, Self: 1, SessionID: mixedRefreshID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer newGenerationSession.Destroy()
	oldGenerationSession, oldOut, err := startCGGMP21Refresh(original[2], tss.ThresholdConfig{
		Threshold: 2, Parties: parties, Self: 2, SessionID: mixedRefreshID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer oldGenerationSession.Destroy()
	if bytes.Equal(newGenerationSession.planHash, oldGenerationSession.planHash) {
		t.Fatal("mixed source generations produced the same refresh plan hash")
	}

	oldCommitment := mustCGGMPEnvelope(t, oldOut, payloadRefreshCommitments, tss.BroadcastPartyId)
	out, err := newGenerationSession.Handle(testutil.DeliverEnvelope(oldCommitment))
	if len(out) != 0 {
		t.Fatalf("mixed-generation commitment emitted %d envelopes", len(out))
	}
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if !errors.Is(protocolErr.Err, errPlanHashMismatch) {
		t.Fatalf("mixed-generation commitment error = %v, want plan mismatch", protocolErr.Err)
	}
	remote := newGenerationSession.partyData[2]
	if remote.commitments != nil || remote.share != nil ||
		remote.paillierPub.PublicKey != nil || remote.paillierPub.Proof != nil ||
		remote.ringPedersen.Params != nil || remote.ringPedersen.Proof != nil {
		t.Fatal("mixed-generation commitment mutated remote refresh state")
	}
	if newGenerationSession.sharesSent || newGenerationSession.newShare != nil || newGenerationSession.completed || newGenerationSession.aborted {
		t.Fatal("mixed-generation commitment advanced or terminated refresh session")
	}
}

func TestCGGMP21KeygenMixedPlanHashRejectsWithoutStateMutation(t *testing.T) {
	sessionID := cggmpPlanTestSession(0x61)
	parties := tss.NewPartySet(1, 2, 3)
	plan1Security := testSecurityParams()
	plan1, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2, Limits: testLimitsPtr(), SecurityParams: &plan1Security})
	if err != nil {
		t.Fatal(err)
	}
	plan2Security := testSecurityParams()
	plan2Security.MinPaillierBits = 1024
	plan2, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2, Limits: testLimitsPtr(), SecurityParams: &plan2Security})
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

	env := out2[0]
	beforeShares := countNonNilShares(s1.round1)
	beforeCommits := countNonNilCommits(s1.round1)
	beforePaillier := countNonNilPaillierPubs(s1.round1)
	out, err := s1.Handle(testutil.DeliverEnvelope(env))
	if len(out) != 0 {
		t.Fatalf("plan mismatch emitted %d envelopes", len(out))
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if countNonNilShares(s1.round1) != beforeShares || countNonNilCommits(s1.round1) != beforeCommits || countNonNilPaillierPubs(s1.round1) != beforePaillier {
		t.Fatal("plan mismatch mutated keygen state")
	}
	if s1.aborted {
		t.Fatal("plan mismatch aborted keygen session")
	}
}

func countNonNilShares(in *keygenRound1Inbox) int {
	n := 0
	for _, d := range in.slots {
		if d.share != nil {
			n++
		}
	}
	return n
}

func countNonNilCommits(in *keygenRound1Inbox) int {
	n := 0
	for _, d := range in.slots {
		if d.commitments != nil {
			n++
		}
	}
	return n
}

func countNonNilPaillierPubs(in *keygenRound1Inbox) int {
	n := 0
	for _, d := range in.slots {
		if d.paillierPub.PublicKey != nil {
			n++
		}
	}
	return n
}
