package secp256k1

import (
	"reflect"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21KeygenRejectNoMutationInvariant(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	kg1, _, err := startCGGMP21Keygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	}, testCGGMP21Guard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startCGGMP21Keygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	}, testCGGMP21Guard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	bad.Round = 2

	before := snapshotCGGMPKeygenSession(kg1)
	out, err := kg1.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotCGGMPKeygenSession(kg1)

	if err == nil {
		t.Fatal("expected wrong-round keygen commitment to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected keygen message produced %d outbound envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRejectNoMutationInvariant(t *testing.T) {
	h := newHarness(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := startTestPresign(h.shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startTestPresign(h.shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	bad.Round = 2

	before := snapshotCGGMPPresignSession(s1)
	out, err := s1.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotCGGMPPresignSession(s1)

	if err == nil {
		t.Fatal("expected wrong-round presign message to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected presign message produced %d outbound envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21SignRejectNoMutationInvariant(t *testing.T) {
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &SignSession{
		key:       &KeyShare{state: &keyShareState{Party: 1}},
		presign:   &Presign{state: &presignState{Signers: signers}},
		sessionID: sessionID,
		guard:     testCGGMP21Guard(1, signers, sessionID),
		partials:  make(map[tss.PartyID]secp.Scalar),
	}
	bad, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       2,
		From:        2,
		To:          tss.BroadcastPartyId,
		PayloadType: payloadSignPartial,
		Payload:     []byte("wrong round"),
	})
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPSignSession(s)
	out, err := s.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotCGGMPSignSession(s)

	if err == nil {
		t.Fatal("expected wrong-round sign partial to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected sign message produced %d outbound envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func assertCGGMPSnapshotUnchanged[T any](t *testing.T, before, after T) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected input mutated session state\nbefore: %+v\nafter:  %+v", before, after)
	}
}
