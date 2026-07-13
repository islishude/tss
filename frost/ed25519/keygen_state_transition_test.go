package ed25519

import (
	"bytes"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTKeygenCommitmentBuildDoesNotMutate(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	commitment := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)

	before := snapshotFROSTKeygenSession(session)
	tx, err := session.buildKeygenTransition(testutil.DeliverEnvelope(commitment))
	after := snapshotFROSTKeygenSession(session)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.cleanupOnReject()
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTKeygenInvalidChainCodeCommitRejectDoesNotMutate(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	bad := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)
	var err error
	bad.Payload, err = testutil.RewriteWireFieldByName(
		bad.Payload,
		keygenCommitmentsPayloadWireType,
		keygenCommitmentsPayload{},
		"ChainCodeCommit",
		[]byte{0x01},
	)
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotFROSTKeygenSession(session)
	out, err := session.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotFROSTKeygenSession(session)
	if err == nil {
		t.Fatal("expected invalid chain-code commitment to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected commitment produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTKeygenShareBuildOwnsAndClearsDecodedSecret(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	share := mustFROSTEnvelope(t, remoteOut, payloadKeygenShare, session.cfg.Self)

	before := snapshotFROSTKeygenSession(session)
	genericTx, err := session.buildKeygenTransition(testutil.DeliverEnvelope(share))
	after := snapshotFROSTKeygenSession(session)
	if err != nil {
		t.Fatal(err)
	}
	tx, ok := genericTx.(*acceptKeygenShareTx)
	if !ok {
		t.Fatalf("transition type = %T, want *acceptKeygenShareTx", genericTx)
	}
	assertFROSTSnapshotUnchanged(t, before, after)
	if tx.share == nil || testutil.IsZeroBytes(tx.share.FixedBytes()) {
		t.Fatal("built share transition does not own the decoded share")
	}
	stagedShare := tx.share
	tx.cleanupOnReject()
	if tx.share != nil {
		t.Fatal("rejected share transition retained decoded share ownership")
	}
	if !testutil.IsZeroBytes(stagedShare.FixedBytes()) {
		t.Fatal("rejected share transition did not clear the decoded share")
	}
}

func TestFROSTKeygenPendingPrepareDoesNotMutateAndDestroysStagedShare(t *testing.T) {
	t.Parallel()

	session1, out1, session2, out2 := frostTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	installFROSTKeygenRound1(t, session1, out2)
	installFROSTKeygenRound1(t, session2, out1)

	before := snapshotFROSTKeygenSession(session1)
	snap, ok, err := session1.round1.snapshot()
	if err != nil || !ok {
		t.Fatalf("round1 snapshot: ok=%v err=%v", ok, err)
	}
	defer snap.Destroy()
	prepared, err := session1.preparePendingKeyMaterial(snap)
	after := snapshotFROSTKeygenSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil {
		t.Fatal("complete round-1 state did not prepare a pending key share")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
	stagedSecret := prepared.pending.secret
	if stagedSecret == nil || testutil.IsZeroBytes(stagedSecret.FixedBytes()) {
		t.Fatal("prepared pending key share has no staged secret")
	}
	prepared.destroy()
	if !testutil.IsZeroBytes(stagedSecret.FixedBytes()) {
		t.Fatal("destroying prepared pending key share did not clear its secret")
	}
}

func TestFROSTKeygenFinalPrepareFailureDoesNotInstallKeyShare(t *testing.T) {
	t.Parallel()

	session1, out1, session2, out2 := frostTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	installFROSTKeygenRound1(t, session1, out2)
	installFROSTKeygenRound1(t, session2, out1)
	_, err := session1.tryAdvance()
	if err != nil {
		t.Fatal(err)
	}
	remoteConfirmations, err := session2.tryAdvance()
	if err != nil {
		t.Fatal(err)
	}
	remoteEnv := mustFROSTEnvelope(t, remoteConfirmations, payloadKeygenConfirmation, tss.BroadcastPartyId)
	remoteConfirmation, err := tss.DecodeBinary[KeygenConfirmation](remoteEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	remoteConfirmation.TranscriptHash = bytes.Clone(remoteConfirmation.TranscriptHash)
	remoteConfirmation.TranscriptHash[0] ^= 1
	session1.confirmations.chainCodes[session2.cfg.Self] = bytes.Clone(remoteConfirmation.ChainCode)
	session1.confirmations.confirmations[session2.cfg.Self] = remoteConfirmation

	before := snapshotFROSTKeygenSession(session1)
	confirmationSnap, ok, snapErr := session1.confirmations.snapshot()
	if snapErr != nil || !ok {
		t.Fatalf("confirmation snapshot: ok=%v err=%v", ok, snapErr)
	}
	defer confirmationSnap.Destroy()
	prepared, err := session1.buildFinalKeyShare(confirmationSnap)
	after := snapshotFROSTKeygenSession(session1)
	if err == nil {
		if prepared != nil {
			prepared.destroy()
		}
		t.Fatal("expected mismatched confirmation to fail final preparation")
	}
	if prepared != nil {
		t.Fatal("failed final preparation returned a staged key share")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTKeygenAggregateIdentityAbortsAndClearsSecrets(t *testing.T) {
	tests := []struct {
		name            string
		commitmentFirst bool
	}{
		{name: "share arrives last", commitmentFirst: true},
		{name: "commitment arrives last", commitmentFirst: false},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parties := tss.NewPartySet(1, 2)
			sessionID := testutil.MustSessionID(int64(840 + i))
			session, _, err := startFROSTKeygen(tss.ThresholdConfig{
				Threshold: 2,
				Parties:   parties,
				Self:      1,
				SessionID: sessionID,
				Rand:      testutil.DeterministicReader(int64(850 + i)),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Destroy()

			commitment, share := maliciousFROSTIdentityAggregateEnvelopes(t, session, 2)
			first, last := share, commitment
			if tc.commitmentFirst {
				first, last = commitment, share
			}
			if out, err := session.Handle(testutil.DeliverEnvelope(first)); err != nil {
				t.Fatalf("first aggregate-identity input rejected early: %v", err)
			} else if len(out) != 0 {
				t.Fatalf("first aggregate-identity input produced %d outbound envelopes", len(out))
			}

			out, err := session.Handle(testutil.DeliverEnvelope(last))
			protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
			if protocolErr.Blame != nil {
				t.Fatal("aggregate identity incorrectly blamed one dealer")
			}
			if len(out) != 0 {
				t.Fatalf("aggregate identity produced %d outbound envelopes", len(out))
			}
			if !session.aborted || session.completed || session.state != keygenAborted {
				t.Fatal("aggregate identity did not leave keygen terminally aborted")
			}
			if session.local != nil || session.pending != nil || session.keyShare != nil {
				t.Fatal("aggregate identity retained local or assembled secret material")
			}
			for _, slot := range session.round1.slots {
				if slot.share != nil {
					t.Fatal("aggregate identity retained a round-1 secret share slot")
				}
			}
			if session.Completed() {
				t.Fatal("aborted aggregate-identity session reported completed")
			}
		})
	}
}

func maliciousFROSTIdentityAggregateEnvelopes(t *testing.T, session *KeygenSession, dealer tss.PartyID) (tss.Envelope, tss.Envelope) {
	t.Helper()
	if session.local == nil || session.local.commitments == nil {
		t.Fatal("missing local commitments for aggregate-identity fixture")
	}
	honestConstant, err := session.local.commitments.PointAt(0)
	if err != nil {
		t.Fatal(err)
	}
	constantCommitment := fed.NewIdentityPoint().Negate(honestConstant)
	shareValue := edcurve.ScalarFromUint64(7)
	defer shareValue.Set(fed.NewScalar())
	shareCommitment := fed.NewIdentityPoint().ScalarBaseMult(shareValue)
	linearCommitment := fed.NewIdentityPoint().Subtract(shareCommitment, constantCommitment)

	commitments, err := newKeygenCommitmentsFromPoints([]*fed.Point{
		constantCommitment,
		linearCommitment,
	}, session.cfg.Threshold)
	if err != nil {
		t.Fatal(err)
	}
	chainCode := bytes.Repeat([]byte{0x5a}, 32)
	t.Cleanup(func() { clear(chainCode) })
	commitPayload, err := marshalKeygenCommitmentsPayloadWithLimits(keygenCommitmentsPayload{
		Commitments:     commitments,
		ChainCodeCommit: bip32util.ChainCodeCommitment(frostChainCodeCommitLabel, session.cfg.SessionID, dealer, chainCode),
		PlanHash:        bytes.Clone(session.planHash),
	}, session.limits)
	if err != nil {
		t.Fatal(err)
	}
	commitmentEnvelope, err := newEnvelope(session.cfg, keygenStartRound, dealer, tss.BroadcastPartyId, payloadKeygenCommitments, commitPayload)
	clear(commitPayload)
	if err != nil {
		t.Fatal(err)
	}

	secretShare, err := newEdSecretScalarFromFed(shareValue)
	if err != nil {
		t.Fatal(err)
	}
	sharePayload, err := marshalKeygenSharePayloadWithLimits(keygenSharePayload{
		Share:    secretShare,
		PlanHash: bytes.Clone(session.planHash),
	}, session.limits)
	secretShare.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	shareEnvelope, err := newEnvelope(session.cfg, keygenStartRound, dealer, session.cfg.Self, payloadKeygenShare, sharePayload)
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

func frostKeygenTransitionSessions(t *testing.T) (*KeygenSession, []tss.Envelope) {
	t.Helper()
	session1, _, session2, out2 := frostTwoPartyKeygenSessions(t)
	session2.Destroy()
	return session1, out2
}

func frostTwoPartyKeygenSessions(t *testing.T) (*KeygenSession, []tss.Envelope, *KeygenSession, []tss.Envelope) {
	t.Helper()
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	}, testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	session2, out2, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	}, testFROSTGuard(2, parties, sessionID))
	if err != nil {
		session1.Destroy()
		t.Fatal(err)
	}
	return session1, out1, session2, out2
}

func installFROSTKeygenRound1(t *testing.T, session *KeygenSession, remoteOut []tss.Envelope) {
	t.Helper()
	commitmentEnv := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)
	commitment, err := unmarshalKeygenCommitmentsPayload(commitmentEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	shareEnv := mustFROSTEnvelope(t, remoteOut, payloadKeygenShare, session.cfg.Self)
	share, err := unmarshalKeygenSharePayload(shareEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	slot := session.round1.slots[commitmentEnv.From]
	commitments := commitment.Commitments.Clone()
	slot.commitments = &commitments
	slot.chainCodeCommit = bytes.Clone(commitment.ChainCodeCommit)
	slot.share = share.Share
}

func mustFROSTEnvelope(t *testing.T, envelopes []tss.Envelope, payloadType tss.PayloadType, to tss.PartyID) tss.Envelope {
	t.Helper()
	for _, env := range envelopes {
		if env.PayloadType == payloadType && env.To == to {
			return env
		}
	}
	t.Fatalf("missing envelope type %q to %d", payloadType, to)
	return tss.Envelope{}
}
