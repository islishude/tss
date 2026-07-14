package ed25519

import (
	"bytes"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
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
	session1.oldPublicKey = PublicKeyPoint{p: fed.NewGeneratorPoint()}
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

func TestFROSTRefreshIdentityVerificationShareAbortsAndClearsSecrets(t *testing.T) {
	for _, commitmentFirst := range []bool{true, false} {
		name := "share arrives last"
		if !commitmentFirst {
			name = "commitment arrives last"
		}
		t.Run(name, func(t *testing.T) {
			session, _, remote, _ := frostTwoPartyRefreshSessions(t)
			defer session.Destroy()
			defer remote.Destroy()

			commitment, share := maliciousFROSTRefreshIdentityVerificationShareEnvelopes(t, session, 2)
			first, last := share, commitment
			if commitmentFirst {
				first, last = commitment, share
			}
			if out, err := session.Handle(testutil.DeliverEnvelope(first)); err != nil {
				t.Fatalf("first verification-identity input rejected early: %v", err)
			} else if len(out) != 0 {
				t.Fatalf("first verification-identity input produced %d outbound envelopes", len(out))
			}

			out, err := session.Handle(testutil.DeliverEnvelope(last))
			protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
			if protocolErr.Blame != nil || protocolErr.Party != tss.BroadcastPartyId {
				t.Fatalf("aggregate verification identity was attributed to one dealer: %#v", protocolErr)
			}
			if len(out) != 0 {
				t.Fatalf("aggregate verification identity produced %d outbound envelopes", len(out))
			}
			if !session.aborted || session.completed {
				t.Fatal("aggregate verification identity did not leave refresh terminally aborted")
			}
			if len(session.shares) != 0 || session.pendingShare != nil || session.newShare != nil {
				t.Fatal("aggregate verification identity retained refresh secret material")
			}
		})
	}
}

func maliciousFROSTRefreshIdentityVerificationShareEnvelopes(t *testing.T, session *ReshareSession, dealer tss.PartyID) (tss.Envelope, tss.Envelope) {
	t.Helper()
	if session.oldKey == nil || session.shares[session.selfID] == nil || session.commits[session.selfID].Len() == 0 {
		t.Fatal("missing local refresh material for verification-identity fixture")
	}

	oldShare, err := session.oldKey.secretScalar()
	if err != nil {
		t.Fatal(err)
	}
	defer oldShare.Set(fed.NewScalar())
	localRefreshShare, err := edScalarFromSecret(session.shares[session.selfID])
	if err != nil {
		t.Fatal(err)
	}
	defer localRefreshShare.Set(fed.NewScalar())
	finalWithoutRemote := fed.NewScalar().Add(oldShare, localRefreshShare)
	defer finalWithoutRemote.Set(fed.NewScalar())
	remoteShare := fed.NewScalar().Subtract(fed.NewScalar(), finalWithoutRemote)
	defer remoteShare.Set(fed.NewScalar())
	remoteEvaluation := fed.NewIdentityPoint().ScalarBaseMult(remoteShare)

	commitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewIdentityPoint(), remoteEvaluation},
		session.newThreshold,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitPayload, err := marshalReshareCommitmentsPayloadWithLimits(reshareCommitmentsPayload{
		Commitments: commitments,
		PlanHash:    bytes.Clone(session.planHash),
	}, session.limits)
	if err != nil {
		t.Fatal(err)
	}
	commitmentEnvelope, err := newEnvelope(
		session.cfg,
		reshareStartRound,
		dealer,
		tss.BroadcastPartyId,
		payloadReshareCommitments,
		commitPayload,
	)
	clear(commitPayload)
	if err != nil {
		t.Fatal(err)
	}

	secretShare, err := newEdSecretScalarFromFed(remoteShare)
	if err != nil {
		t.Fatal(err)
	}
	sharePayload, err := marshalReshareSharePayloadWithLimits(reshareSharePayload{
		Share:    secretShare,
		PlanHash: bytes.Clone(session.planHash),
	}, session.limits)
	secretShare.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	shareEnvelope, err := newEnvelope(
		session.cfg,
		reshareStartRound,
		dealer,
		session.selfID,
		payloadReshareShare,
		sharePayload,
	)
	clear(sharePayload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clear(commitmentEnvelope.Payload)
		clear(shareEnvelope.Payload)
	})
	return commitmentEnvelope, shareEnvelope
}

func TestFROSTReshareMultipleInvalidDealerSharesBlameCanonicalFirst(t *testing.T) {
	t.Parallel()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	commitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint()},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	badScalar := edcurve.ScalarFromUint64(2)
	defer badScalar.Set(fed.NewScalar())
	badShare1, err := newEdSecretScalarFromFed(badScalar)
	if err != nil {
		t.Fatal(err)
	}
	defer badShare1.Destroy()
	badShare2, err := newEdSecretScalarFromFed(badScalar)
	if err != nil {
		t.Fatal(err)
	}
	defer badShare2.Destroy()

	parties := tss.NewPartySet(1, 2)
	session := &ReshareSession{
		oldParties: parties,
		selfID:     3,
		cfg: tss.ThresholdConfig{
			Threshold: 1,
			Parties:   parties,
			Self:      3,
			SessionID: sessionID,
		},
		// Insert both maps in reverse dealer order. Verification must follow
		// oldParties, never either map's iteration order.
		commits: map[tss.PartyID]reshareCommitments{
			2: commitments.Clone(),
			1: commitments.Clone(),
		},
		shares: map[tss.PartyID]*secret.Scalar{
			2: badShare2,
			1: badShare1,
		},
	}

	protocolErr := assertFROSTProtocolCode(t, session.verifyReshareDealerShares(), tss.ErrCodeVerification)
	if protocolErr.Party != 1 {
		t.Fatalf("blamed dealer %d, want canonical first invalid dealer 1", protocolErr.Party)
	}
	if protocolErr.Blame == nil || len(protocolErr.Blame.Parties) != 1 || protocolErr.Blame.Parties[0] != 1 {
		t.Fatalf("blame parties = %v, want [1]", protocolErr.Blame)
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

func TestFROSTReshareDealerOnlyWaitsForTargetConfirmations(t *testing.T) {
	t.Parallel()

	oldShares := frostKeygen(t, 2, 3)
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	allParties := tss.MergePartySet(oldParties, newParties)
	sessions := make(map[tss.PartyID]*ReshareSession, len(allParties))
	messages := make([]tss.Envelope, 0)
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
		messages = append(messages, out...)
	}
	recipient, err := startFROSTReshareRecipient(oldShares[1], oldParties, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      4,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer recipient.Destroy()
	sessions[4] = recipient

	dealerOnly := sessions[1]
	if len(dealerOnly.shares) != 0 {
		t.Fatal("dealer-only session retained an unnecessary local share")
	}
	confirmations := make([]tss.Envelope, 0, len(newParties))
	for _, env := range messages {
		for _, id := range allParties {
			if id == env.From || (env.To != tss.BroadcastPartyId && env.To != id) {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver round 1 %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			for _, produced := range out {
				if produced.PayloadType == payloadReshareConfirmation {
					confirmations = append(confirmations, produced)
				}
			}
		}
	}
	if dealerOnly.completed || dealerOnly.confirmationBinding == nil || dealerOnly.newShare != nil {
		t.Fatal("dealer-only session did not wait on the public target confirmation binding")
	}
	if len(confirmations) != len(newParties) {
		t.Fatalf("got %d target confirmations, want %d", len(confirmations), len(newParties))
	}
	for _, env := range confirmations {
		for _, id := range allParties {
			if id == env.From {
				continue
			}
			if _, err := sessions[id].Handle(testutil.DeliverEnvelope(env)); err != nil {
				t.Fatalf("deliver confirmation from %d to %d: %v", env.From, id, err)
			}
		}
	}
	if !dealerOnly.Completed() || dealerOnly.newShare != nil {
		t.Fatal("dealer-only session did not complete after all target confirmations")
	}
	if _, ok := dealerOnly.KeyShare(); ok {
		t.Fatal("dealer-only session exposed a key share")
	}
}

func TestFROSTReshareDealerOnlyConfirmationBindingRejectsMismatches(t *testing.T) {
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
	for _, id := range tss.NewPartySet(2, 3) {
		remote, out, err := startFROSTReshare(oldShares[id], newParties, 2, tss.ThresholdConfig{
			Threshold: 2,
			Parties:   oldParties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer remote.Destroy()
		commitment := mustFROSTEnvelope(t, out, payloadReshareCommitments, tss.BroadcastPartyId)
		if _, err := dealerOnly.Handle(testutil.DeliverEnvelope(commitment)); err != nil {
			t.Fatal(err)
		}
	}
	if dealerOnly.confirmationBinding == nil || dealerOnly.completed {
		t.Fatal("dealer-only session did not stage a public confirmation binding")
	}

	tests := []struct {
		name   string
		mutate func(*KeygenConfirmation)
	}{
		{name: "transcript hash", mutate: func(c *KeygenConfirmation) {
			c.TranscriptHash = bytes.Clone(c.TranscriptHash)
			c.TranscriptHash[0] ^= 1
		}},
		{name: "commitments hash", mutate: func(c *KeygenConfirmation) {
			c.CommitmentsHash = bytes.Clone(c.CommitmentsHash)
			c.CommitmentsHash[0] ^= 1
		}},
		{name: "target set", mutate: func(c *KeygenConfirmation) {
			c.Parties = tss.NewPartySet(2, 3, 5)
		}},
		{name: "chain code", mutate: func(c *KeygenConfirmation) {
			c.ChainCode = bytes.Clone(c.ChainCode)
			c.ChainCode[0] ^= 1
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			confirmation := dealerOnly.confirmationBinding.confirmation(2)
			tc.mutate(confirmation)
			before := snapshotFROSTReshareSession(dealerOnly)
			if err := dealerOnly.confirmationBinding.verify(confirmation); err == nil {
				t.Fatal("mismatched target confirmation was accepted")
			}
			after := snapshotFROSTReshareSession(dealerOnly)
			assertFROSTSnapshotUnchanged(t, before, after)
			clear(confirmation.ChainCode)
		})
	}

	valid := dealerOnly.confirmationBinding.confirmation(2)
	payload, err := valid.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       reshareConfirmationRound,
		From:        2,
		To:          tss.BroadcastPartyId,
		PayloadType: payloadReshareConfirmation,
		Payload:     payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := dealerOnly.buildAcceptReshareConfirmationTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.apply(dealerOnly); err != nil {
		t.Fatal(err)
	}
	tx.markCommitted()
	before := snapshotFROSTReshareSession(dealerOnly)
	duplicate, err := dealerOnly.buildAcceptReshareConfirmationTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.duplicate {
		t.Fatal("identical target confirmation was not classified as a duplicate")
	}
	conflicting := valid.Clone()
	conflicting.TranscriptHash[0] ^= 1
	conflictingPayload, err := conflicting.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = conflictingPayload
	if _, err := dealerOnly.buildAcceptReshareConfirmationTx(env); err == nil {
		t.Fatal("conflicting target confirmation was accepted")
	}
	after := snapshotFROSTReshareSession(dealerOnly)
	assertFROSTSnapshotUnchanged(t, before, after)
	clear(valid.ChainCode)
	clear(conflicting.ChainCode)
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
