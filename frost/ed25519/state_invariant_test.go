package ed25519

import (
	"reflect"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTKeygenMalformedCommitmentTerminallyAbortsAndClearsSecrets(t *testing.T) {
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

	out, err := kg1.Handle(testutil.DeliverEnvelope(bad))

	if err == nil {
		t.Fatal("expected malformed keygen commitment to be rejected")
	}
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if protocolErr.Party != bad.From || protocolErr.Blame == nil {
		t.Fatalf("malformed keygen commitment blame = %#v, want party %d", protocolErr.Blame, bad.From)
	}
	if len(out) != 0 {
		t.Fatalf("rejected keygen message produced %d outbound envelopes", len(out))
	}
	if !kg1.aborted || kg1.state != keygenAborted || kg1.local != nil || kg1.pending != nil || kg1.keyShare != nil {
		t.Fatal("malformed keygen commitment did not terminally abort and clear secret state")
	}
	for _, slot := range kg1.round1.slots {
		if slot.share != nil {
			t.Fatal("malformed keygen commitment retained a secret share slot")
		}
	}
}

func TestFROSTKeygenMalformedShareTerminallyAbortsAndClearsSecrets(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	bad := mustFROSTEnvelope(t, remoteOut, payloadKeygenShare, session.cfg.Self)
	bad.Payload = []byte("malformed confidential keygen share")

	out, err := session.Handle(testutil.DeliverEnvelope(bad))
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if protocolErr.Round != keygenShareRound || protocolErr.Party != bad.From || protocolErr.Blame == nil {
		t.Fatalf("malformed keygen share error = %#v", protocolErr)
	}
	if len(out) != 0 {
		t.Fatalf("malformed keygen share produced %d outbound envelopes", len(out))
	}
	if !session.aborted || session.state != keygenAborted || session.local != nil || session.pending != nil || session.keyShare != nil {
		t.Fatal("malformed keygen share did not terminally abort and clear secret state")
	}
	for _, slot := range session.round1.slots {
		if slot.share != nil {
			t.Fatal("malformed keygen share retained a secret share slot")
		}
	}
}

func TestFROSTSignMalformedCommitmentAbortsAndClearsSecrets(t *testing.T) {
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

	dNonce := sign1.dNonce
	eNonce := sign1.eNonce
	out, err := sign1.Handle(testutil.DeliverEnvelope(bad))
	if err == nil {
		t.Fatal("expected malformed sign commitment to be rejected")
	}
	protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
	if protocolErr.Blame == nil || len(protocolErr.Blame.Parties) != 1 || protocolErr.Blame.Parties[0] != 2 {
		t.Fatalf("malformed nonce commitment blame = %#v, want party 2", protocolErr.Blame)
	}
	if len(out) != 0 {
		t.Fatalf("rejected sign message produced %d outbound envelopes", len(out))
	}
	if !sign1.aborted || sign1.completed {
		t.Fatal("malformed nonce commitment did not leave signing terminally aborted")
	}
	if sign1.dNonce != nil || sign1.eNonce != nil || dNonce.FixedLen() != 0 || eNonce.FixedLen() != 0 {
		t.Fatal("malformed nonce commitment retained local signing nonces")
	}
	if sign1.derivation != nil || sign1.message != nil {
		t.Fatal("malformed nonce commitment retained signing intent state")
	}
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
	out, err := refresh1.Handle(testutil.DeliverEnvelope(bad))
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
