package ed25519

import (
	"bytes"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTSignCommitmentPlanHashRejectDoesNotMutate(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.parties)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("phase-02"), testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("phase-02"), testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	commitment, err := unmarshalNonceCommitmentPayload(bad.Payload)
	if err != nil {
		t.Fatal(err)
	}
	commitment.PlanHash = bytes.Repeat([]byte{0x42}, 32)
	bad.Payload, err = marshalNonceCommitmentPayload(commitment)
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotFROSTSignSession(sign1)
	out, err := sign1.HandleSignMessage(testutil.DeliverEnvelope(bad))
	after := snapshotFROSTSignSession(sign1)

	if err == nil {
		t.Fatal("expected sign commitment plan hash mismatch to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected sign commitment produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignLocalPartialPrepareFailureDoesNotCommit(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.parties)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("phase-02"), testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("phase-02"), testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := unmarshalNonceCommitmentPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	sign1.commitments[2] = commitment
	sign1.planHash = []byte{0x01}

	before := snapshotFROSTSignSession(sign1)
	prepared, ok, err := sign1.prepareLocalPartial()
	after := snapshotFROSTSignSession(sign1)

	if err == nil {
		t.Fatal("expected local partial prepare to fail")
	}
	if ok || prepared != nil {
		t.Fatal("failed prepare returned a prepared partial")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignAggregateFailureDoesNotCommit(t *testing.T) {
	t.Parallel()

	signers := tss.NewPartySet(1, 2)
	sessions, _ := frostSigningRound2(t, 2, 3, signers, []byte("phase-02"))
	session := sessions[1]
	session.partials[2] = fed.NewScalar()

	before := snapshotFROSTSignSession(session)
	err := session.tryAggregate()
	after := snapshotFROSTSignSession(session)

	if err == nil {
		t.Fatal("expected aggregate with invalid partial to fail")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}
