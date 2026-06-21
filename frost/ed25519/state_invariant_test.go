package ed25519

import (
	"reflect"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTKeygenRejectNoMutationInvariant(t *testing.T) {
	t.Parallel()

	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	kg1, _, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	}, testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	}, testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	bad.Payload = []byte("malformed keygen commitments")

	before := snapshotFROSTKeygenSession(kg1)
	out, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(bad))
	after := snapshotFROSTKeygenSession(kg1)

	if err == nil {
		t.Fatal("expected malformed keygen commitment to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected keygen message produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignRejectNoMutationInvariant(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.Parties)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("phase-00"), testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("phase-00"), testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	bad.Payload = []byte("malformed nonce commitment")

	before := snapshotFROSTSignSession(sign1)
	out, err := sign1.HandleSignMessage(testutil.DeliverEnvelope(bad))
	after := snapshotFROSTSignSession(sign1)

	if err == nil {
		t.Fatal("expected malformed sign commitment to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected sign message produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTReshareRejectNoMutationInvariant(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.NewPartySet(1, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	refresh1, _, err := startFROSTRefresh(shares[1], tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	}, testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTRefresh(shares[2], tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	}, testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	bad.Payload = []byte("malformed reshare commitments")

	before := snapshotFROSTReshareSession(refresh1)
	out, err := refresh1.HandleReshareMessage(testutil.DeliverEnvelope(bad))
	after := snapshotFROSTReshareSession(refresh1)

	if err == nil {
		t.Fatal("expected malformed refresh commitment to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected refresh message produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func assertFROSTSnapshotUnchanged[T any](t *testing.T, before, after T) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected input mutated session state\nbefore: %+v\nafter:  %+v", before, after)
	}
}
