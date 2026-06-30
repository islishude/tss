package ed25519

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
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
