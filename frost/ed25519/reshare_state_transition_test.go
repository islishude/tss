package ed25519

import (
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTReshareModeAndRoleAreExplicit(t *testing.T) {
	t.Parallel()

	oldShares := frostKeygen(t, 2, 3)
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	dealerOnly, _, err := startFROSTReshare(oldShares[1], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dealerOnly.Destroy()
	if dealerOnly.mode != frostReshareModeReshare || dealerOnly.role != frostReshareRoleDealerOnly {
		t.Fatalf("dealer-only mode/role = %d/%d", dealerOnly.mode, dealerOnly.role)
	}
	if !dealerOnly.isDealer() || dealerOnly.isRecipient() || dealerOnly.requiresInboundShares() {
		t.Fatal("dealer-only role predicates are inconsistent")
	}

	dealerRecipient, _, err := startFROSTReshare(oldShares[2], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      2,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dealerRecipient.Destroy()
	if dealerRecipient.role != frostReshareRoleDealerAndRecipient || !dealerRecipient.isDealer() || !dealerRecipient.isRecipient() {
		t.Fatal("dealer-recipient role predicates are inconsistent")
	}

	recipientOnly, err := startFROSTReshareRecipient(
		oldShares[1],
		oldParties,
		newParties,
		2,
		tss.ThresholdConfig{
			Threshold: 2,
			Parties:   newParties,
			Self:      4,
			SessionID: sessionID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer recipientOnly.Destroy()
	if recipientOnly.role != frostReshareRoleRecipientOnly || recipientOnly.isDealer() || !recipientOnly.isRecipient() {
		t.Fatal("recipient-only role predicates are inconsistent")
	}

	refreshID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, err := startFROSTRefresh(oldShares[1], tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      1,
		SessionID: refreshID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer refresh.Destroy()
	if refresh.mode != frostReshareModeRefresh || refresh.role != frostReshareRoleDealerAndRecipient || !refresh.isRefresh() {
		t.Fatal("refresh mode/role predicates are inconsistent")
	}
}

func TestFROSTReshareCommitmentBuildDoesNotMutate(t *testing.T) {
	t.Parallel()

	session1, _, session2, out2 := frostTwoPartyRefreshSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	commitment := mustFROSTEnvelope(t, out2, payloadReshareCommitments, tss.BroadcastPartyId)

	before := snapshotFROSTReshareSession(session1)
	tx, err := session1.buildReshareTransition(testutil.DeliverEnvelope(commitment))
	after := snapshotFROSTReshareSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.cleanupOnReject()
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTReshareShareBuildOwnsAndClearsDecodedSecret(t *testing.T) {
	t.Parallel()

	session1, _, session2, out2 := frostTwoPartyRefreshSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	share := mustFROSTEnvelope(t, out2, payloadReshareShare, session1.selfID)

	before := snapshotFROSTReshareSession(session1)
	genericTx, err := session1.buildReshareTransition(testutil.DeliverEnvelope(share))
	after := snapshotFROSTReshareSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	tx, ok := genericTx.(*acceptReshareShareTx)
	if !ok {
		t.Fatalf("transition type = %T, want *acceptReshareShareTx", genericTx)
	}
	assertFROSTSnapshotUnchanged(t, before, after)
	staged := tx.share
	if staged == nil || testutil.IsZeroBytes(staged.FixedBytes()) {
		t.Fatal("built share transition does not own the decoded share")
	}
	tx.cleanupOnReject()
	if tx.share != nil || !testutil.IsZeroBytes(staged.FixedBytes()) {
		t.Fatal("rejected share transition did not clear decoded share ownership")
	}
}

func TestFROSTReshareShareApplyRollsBackOnCompletionError(t *testing.T) {
	t.Parallel()

	session1, _, session2, out2 := frostTwoPartyRefreshSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	commitment := mustFROSTEnvelope(t, out2, payloadReshareCommitments, tss.BroadcastPartyId)
	if _, err := session1.Handle(testutil.DeliverEnvelope(commitment)); err != nil {
		t.Fatal(err)
	}

	// Force a non-ProtocolError completion failure after the decoded share has
	// been staged. The transition must remove the staged map entry before its
	// rejection cleanup destroys the scalar.
	session1.oldPublicKey = publicKeyPoint{p: fed.NewGeneratorPoint()}
	share := mustFROSTEnvelope(t, out2, payloadReshareShare, session1.selfID)
	genericTx, err := session1.buildReshareTransition(testutil.DeliverEnvelope(share))
	if err != nil {
		t.Fatal(err)
	}
	tx := genericTx.(*acceptReshareShareTx)
	staged := tx.share
	if _, err := tx.apply(session1); err == nil {
		t.Fatal("expected completion failure")
	}
	if _, ok := session1.shares[share.From]; ok {
		t.Fatal("failed reshare transition retained the staged share")
	}
	tx.cleanupOnReject()
	if !testutil.IsZeroBytes(staged.FixedBytes()) {
		t.Fatal("failed reshare transition did not destroy the staged share")
	}
}

func TestFROSTReshareBuffersConfirmationUntilRound1Completes(t *testing.T) {
	t.Parallel()

	session1, out1, session2, out2 := frostTwoPartyRefreshSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()

	var confirmation tss.Envelope
	for _, env := range out1 {
		out, err := session2.Handle(testutil.DeliverEnvelope(env))
		if err != nil {
			t.Fatal(err)
		}
		for _, produced := range out {
			if produced.PayloadType == payloadReshareConfirmation {
				confirmation = produced
			}
		}
	}
	if confirmation.PayloadType == "" {
		t.Fatal("remote refresh session did not emit a confirmation")
	}
	if _, err := session1.Handle(testutil.DeliverEnvelope(confirmation)); err != nil {
		t.Fatal(err)
	}
	if session1.pendingConfirmations[2] == nil {
		t.Fatal("early reshare confirmation was not buffered")
	}

	for _, env := range out2 {
		if _, err := session1.Handle(testutil.DeliverEnvelope(env)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := session1.KeyShare(); !ok {
		t.Fatal("buffered confirmation was not revalidated to complete refresh")
	}
}

func TestFROSTReshareDealerOnlyRejectsInboundShareWithoutMutation(t *testing.T) {
	t.Parallel()

	oldShares := frostKeygen(t, 2, 3)
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	dealerOnly, _, err := startFROSTReshare(oldShares[1], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dealerOnly.Destroy()
	_, out2, err := startFROSTReshare(oldShares[2], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      2,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	share := mustFROSTEnvelope(t, out2, payloadReshareShare, 4)
	share.To = 1

	before := snapshotFROSTReshareSession(dealerOnly)
	out, err := dealerOnly.Handle(testutil.DeliverEnvelope(share))
	after := snapshotFROSTReshareSession(dealerOnly)
	if err == nil {
		t.Fatal("expected dealer-only session to reject inbound share")
	}
	if len(out) != 0 {
		t.Fatalf("rejected share produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTReshareRejectsShareFromNonDealerWithoutMutation(t *testing.T) {
	t.Parallel()

	oldShares := frostKeygen(t, 2, 3)
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := startFROSTReshareRecipient(
		oldShares[1],
		oldParties,
		newParties,
		2,
		tss.ThresholdConfig{
			Threshold: 2,
			Parties:   newParties,
			Self:      4,
			SessionID: sessionID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer recipient.Destroy()
	dealer, dealerOut, err := startFROSTReshare(oldShares[1], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dealer.Destroy()
	share := mustFROSTEnvelope(t, dealerOut, payloadReshareShare, 4)
	share.From = 99

	before := snapshotFROSTReshareSession(recipient)
	out, err := recipient.Handle(testutil.DeliverEnvelope(share))
	after := snapshotFROSTReshareSession(recipient)
	if err == nil {
		t.Fatal("expected share from non-dealer to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected share produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTReshareDealerOnlyCompletionNeedsOnlyCommitments(t *testing.T) {
	t.Parallel()

	oldShares := frostKeygen(t, 2, 3)
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*ReshareSession, len(oldParties))
	outputs := make(map[tss.PartyID][]tss.Envelope, len(oldParties))
	for _, id := range oldParties {
		session, out, err := startFROSTReshare(oldShares[id], newParties, 2, tss.ThresholdConfig{
			Threshold: 2,
			Parties:   oldParties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Destroy()
		sessions[id] = session
		outputs[id] = out
	}
	dealerOnly := sessions[1]
	if len(dealerOnly.shares) != 0 {
		t.Fatal("dealer-only session retained an unnecessary local share")
	}
	for _, id := range tss.NewPartySet(2, 3) {
		env := mustFROSTEnvelope(t, outputs[id], payloadReshareCommitments, tss.BroadcastPartyId)
		if _, err := dealerOnly.Handle(testutil.DeliverEnvelope(env)); err != nil {
			t.Fatal(err)
		}
	}
	if !dealerOnly.completed || dealerOnly.newShare != nil {
		t.Fatal("dealer-only session did not complete from commitments alone")
	}
}

func TestFROSTReshareCompletionPrepareDoesNotMutateAndDestroysStagedShare(t *testing.T) {
	t.Parallel()

	session1, _, session2, out2 := frostTwoPartyRefreshSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	installFROSTReshareRound1(t, session1, out2)

	before := snapshotFROSTReshareSession(session1)
	prepared, ok, err := session1.maybePrepareReshareCompletion()
	after := snapshotFROSTReshareSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || prepared == nil || prepared.newShare == nil {
		t.Fatal("complete refresh state did not prepare a new share")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
	stagedSecret := prepared.newShare.state.Secret
	if stagedSecret == nil || testutil.IsZeroBytes(stagedSecret.FixedBytes()) {
		t.Fatal("prepared reshare completion has no staged secret")
	}
	prepared.destroy()
	if !testutil.IsZeroBytes(stagedSecret.FixedBytes()) {
		t.Fatal("destroying prepared reshare completion did not clear staged secret")
	}
}

func TestFROSTPreparedReshareDealerStartDestroyClearsOwnedState(t *testing.T) {
	t.Parallel()

	session1, out1, session2, _ := frostTwoPartyRefreshSessions(t)
	session2.Destroy()
	ownedOut := tss.CloneSlice(out1)
	prepared := &preparedReshareDealerStart{
		session: session1,
		out:     ownedOut,
	}
	prepared.destroy()

	if !session1.aborted {
		t.Fatal("destroyed prepared reshare start did not abort staged session")
	}
	if len(session1.shares) != 0 {
		t.Fatal("destroyed prepared reshare start retained share scalars")
	}
	for _, env := range ownedOut {
		if !testutil.IsZeroBytes(env.Payload) {
			t.Fatal("destroyed prepared reshare start retained outbound payload")
		}
	}
}

func frostTwoPartyRefreshSessions(t *testing.T) (*ReshareSession, []tss.Envelope, *ReshareSession, []tss.Envelope) {
	t.Helper()
	shares := frostKeygen(t, 2, 2)
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := startFROSTRefresh(shares[1], tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	session2, out2, err := startFROSTRefresh(shares[2], tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	})
	if err != nil {
		session1.Destroy()
		t.Fatal(err)
	}
	return session1, out1, session2, out2
}

func installFROSTReshareRound1(t *testing.T, session *ReshareSession, remoteOut []tss.Envelope) {
	t.Helper()
	commitmentEnv := mustFROSTEnvelope(t, remoteOut, payloadReshareCommitments, tss.BroadcastPartyId)
	commitment, err := unmarshalReshareCommitmentsPayload(commitmentEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	shareEnv := mustFROSTEnvelope(t, remoteOut, payloadReshareShare, session.selfID)
	share, err := unmarshalReshareSharePayload(shareEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	session.commits[commitmentEnv.From] = commitment.Commitments.Clone()
	session.shares[shareEnv.From] = share.Share
}
