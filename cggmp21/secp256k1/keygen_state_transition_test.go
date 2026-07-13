package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21KeygenEarlyShareRejectsWithoutReplayAndRetries(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()

	sharesFrom2, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	share := mustCGGMPEnvelope(t, sharesFrom2, payloadKeygenShare, session1.cfg.Self)
	before := snapshotCGGMPKeygenSession(session1)
	out, err := session1.Handle(testutil.DeliverEnvelope(share))
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeRound {
		t.Fatalf("early keygen share error = %v, want round error", err)
	}
	if len(out) != 0 {
		t.Fatalf("early keygen share emitted %d envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, snapshotCGGMPKeygenSession(session1))

	if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := session1.Handle(testutil.DeliverEnvelope(share)); err != nil {
		t.Fatalf("keygen share retry after commitments: %v", err)
	}
}

func TestCGGMP21KeygenOutboundFailureLeavesStateAndReplayUncommitted(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	if _, err := session2.Handle(testutil.DeliverEnvelope(out1[0])); err != nil {
		t.Fatal(err)
	}

	originalSigner := session1.cfg.EnvelopeSigner
	session1.cfg.EnvelopeSigner = failingPresignEnvelopeSigner{}
	before := snapshotCGGMPKeygenSession(session1)
	if out, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil || len(out) != 0 {
		t.Fatalf("keygen outbound construction failure = out:%d err:%v", len(out), err)
	}
	assertCGGMPSnapshotUnchanged(t, before, snapshotCGGMPKeygenSession(session1))

	session1.cfg.EnvelopeSigner = originalSigner
	if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatalf("retry after keygen outbound construction failure: %v", err)
	}
}

func TestCGGMP21KeygenAcceptedSlotUsesReplayClassification(t *testing.T) {
	t.Run("exact duplicate", func(t *testing.T) {
		session1, _, session2, out2 := cggmpTwoPartyKeygenSessions(t)
		defer session1.Destroy()
		defer session2.Destroy()
		in := testutil.DeliverEnvelope(out2[0])
		if _, err := session1.Handle(in); err != nil {
			t.Fatal(err)
		}
		if _, err := session1.Handle(in); !errors.Is(err, tss.ErrDuplicateMessage) {
			t.Fatalf("accepted exact duplicate = %v, want ErrDuplicateMessage", err)
		}
	})

	t.Run("conflicting duplicate", func(t *testing.T) {
		session1, _, session2, out2 := cggmpTwoPartyKeygenSessions(t)
		defer session1.Destroy()
		defer session2.Destroy()
		if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
			t.Fatal(err)
		}
		conflict := out2[0]
		conflict.Payload = bytes.Clone(conflict.Payload)
		conflict.Payload[len(conflict.Payload)-1] ^= 1
		_, err := session1.Handle(testutil.DeliverEnvelope(conflict))
		var protocolErr *tss.ProtocolError
		if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeVerification || !session1.aborted {
			t.Fatalf("accepted conflicting duplicate = err:%v aborted:%v", err, session1.aborted)
		}
	})
}

func TestCGGMP21KeygenMalformedCommitmentRejectDoesNotMutate(t *testing.T) {
	session1, _, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	bad := out2[0]
	bad.Payload = []byte("malformed keygen commitment")

	before := snapshotCGGMPKeygenSession(session1)
	out, err := session1.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotCGGMPKeygenSession(session1)
	if err == nil {
		t.Fatal("expected malformed keygen commitment to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected keygen commitment produced %d envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21KeygenCommitmentBuildDoesNotMutate(t *testing.T) {
	session1, _, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()

	before := snapshotCGGMPKeygenSession(session1)
	tx, err := session1.buildAcceptCGGMPKeygenCommitmentsTx(out2[0])
	after := snapshotCGGMPKeygenSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.cleanupOnReject()
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21KeygenInvalidProofBuildDoesNotMutate(t *testing.T) {
	session1, _, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	bad := out2[0]
	payload, err := unmarshalKeygenCommitmentsPayload(bad.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierProof.W = bytes.Clone(payload.PaillierProof.W)
	payload.PaillierProof.W[0] ^= 1
	bad.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPKeygenSession(session1)
	tx, err := session1.buildAcceptCGGMPKeygenCommitmentsTx(bad)
	after := snapshotCGGMPKeygenSession(session1)
	if err == nil {
		if tx != nil {
			tx.cleanupOnReject()
		}
		t.Fatal("expected invalid Paillier proof to fail transition build")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21KeygenShareBuildOwnsAndClearsDecodedSecret(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	_, sharesFrom2 := exchangeKeygenCommitmentsForShares(t, session1, out1, session2, out2)
	shareEnv := mustCGGMPEnvelope(t, sharesFrom2, payloadKeygenShare, session1.cfg.Self)

	before := snapshotCGGMPKeygenSession(session1)
	tx, err := session1.buildAcceptCGGMPKeygenShareTx(shareEnv)
	after := snapshotCGGMPKeygenSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
	staged := tx.share
	if staged == nil || testutil.IsZeroBytes(staged.FixedBytes()) {
		t.Fatal("built keygen share transition does not own decoded secret")
	}
	tx.cleanupOnReject()
	if tx.share != nil || !testutil.IsZeroBytes(staged.FixedBytes()) {
		t.Fatal("rejected keygen share transition did not clear decoded secret")
	}
}

func TestCGGMP21KeygenPendingPrepareDoesNotMutateAndDestroysStagedSecrets(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	sharesFrom1, sharesFrom2 := exchangeKeygenCommitmentsForShares(t, session1, out1, session2, out2)
	installCGGMPKeygenShare(t, session1, sharesFrom2)
	installCGGMPKeygenShare(t, session2, sharesFrom1)

	before := snapshotCGGMPKeygenSession(session1)
	prepared, ok, err := session1.maybePrepareCGGMPPendingKeyShare()
	after := snapshotCGGMPKeygenSession(session1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || prepared == nil || prepared.share == nil {
		t.Fatal("complete round-1 state did not prepare a key share")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)

	stagedSecret := prepared.share.state.Secret
	stagedPaillierP := prepared.share.state.PaillierPrivateKey.P
	if stagedSecret == nil || testutil.IsZeroBytes(stagedSecret.FixedBytes()) {
		t.Fatal("prepared key share has no staged secret scalar")
	}
	if stagedPaillierP == nil || testutil.IsZeroBytes(stagedPaillierP.FixedBytes()) {
		t.Fatal("prepared key share has no staged Paillier private material")
	}
	prepared.destroy()
	if !testutil.IsZeroBytes(stagedSecret.FixedBytes()) {
		t.Fatal("destroying prepared key share did not clear secret scalar")
	}
	if !testutil.IsZeroBytes(stagedPaillierP.FixedBytes()) {
		t.Fatal("destroying prepared key share did not clear Paillier private material")
	}
}

func TestCGGMP21KeygenFinalPrepareFailureDoesNotInstallKeyShare(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	sharesFrom1, sharesFrom2 := exchangeKeygenCommitmentsForShares(t, session1, out1, session2, out2)
	installCGGMPKeygenShare(t, session1, sharesFrom2)
	installCGGMPKeygenShare(t, session2, sharesFrom1)

	pending1, ok, err := session1.maybePrepareCGGMPPendingKeyShare()
	if err != nil || !ok {
		t.Fatalf("prepare party 1 pending share: ok=%v err=%v", ok, err)
	}
	defer pending1.destroy()
	if _, err := session1.commitCGGMPPendingKeyShare(pending1); err != nil {
		t.Fatal(err)
	}

	pending2, ok, err := session2.maybePrepareCGGMPPendingKeyShare()
	if err != nil || !ok {
		t.Fatalf("prepare party 2 pending share: ok=%v err=%v", ok, err)
	}
	defer pending2.destroy()
	remoteConfirmation, err := tss.DecodeBinary[KeygenConfirmation](pending2.env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	remoteConfirmation.TranscriptHash = bytes.Clone(remoteConfirmation.TranscriptHash)
	remoteConfirmation.TranscriptHash[0] ^= 1
	if err := session1.confirmations.record(session2.cfg.Self, remoteConfirmation); err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPKeygenSession(session1)
	prepared, ok, err := session1.maybePrepareCGGMPFinalKeyShare()
	after := snapshotCGGMPKeygenSession(session1)
	if err == nil {
		if prepared != nil {
			prepared.destroy()
		}
		t.Fatal("expected mismatched confirmation to fail final preparation")
	}
	if ok || prepared != nil {
		t.Fatal("failed final preparation returned a staged key share")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21KeygenConfirmationBeforePendingIsRevalidatedAndCompletes(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	sharesFrom1, sharesFrom2 := exchangeKeygenCommitmentsForShares(t, session1, out1, session2, out2)
	installCGGMPKeygenShare(t, session2, sharesFrom1)

	pending2, ok, err := session2.maybePrepareCGGMPPendingKeyShare()
	if err != nil || !ok {
		t.Fatalf("prepare party 2 pending share: ok=%v err=%v", ok, err)
	}
	defer pending2.destroy()

	confirmationTx, err := session1.buildAcceptCGGMPKeygenConfirmationTx(pending2.env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confirmationTx.apply(session1); err != nil {
		t.Fatal(err)
	}
	confirmationTx.markCommitted()
	if session1.pending != nil || session1.completed {
		t.Fatal("early confirmation advanced keygen before round1 completed")
	}

	shareEnv := mustCGGMPEnvelope(t, sharesFrom2, payloadKeygenShare, session1.cfg.Self)
	shareTx, err := session1.buildAcceptCGGMPKeygenShareTx(shareEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shareTx.apply(session1); err != nil {
		t.Fatal(err)
	}
	shareTx.markCommitted()
	if !session1.completed || session1.keyShare == nil {
		t.Fatal("buffered confirmation did not complete after pending share construction")
	}
}

func TestCGGMP21PreparedKeygenStartDestroyClearsOwnedState(t *testing.T) {
	session1, out1, session2, _ := cggmpTwoPartyKeygenSessions(t)
	session2.Destroy()
	ownedOut := tss.CloneSlice(out1)
	paillierP := session1.local.paillier.P
	prepared := &preparedCGGMPKeygenStart{
		session: session1,
		out:     ownedOut,
	}
	prepared.destroy()

	if !session1.aborted || session1.local != nil {
		t.Fatal("destroyed prepared keygen start retained live session resources")
	}
	if !testutil.IsZeroBytes(paillierP.FixedBytes()) {
		t.Fatal("destroyed prepared keygen start did not clear Paillier private material")
	}
	for _, pd := range session1.round1.slots {
		if pd.share != nil {
			t.Fatal("destroyed prepared keygen start retained a DKG share")
		}
	}
	for _, env := range ownedOut {
		if !testutil.IsZeroBytes(env.Payload) {
			t.Fatal("destroyed prepared keygen start retained outbound payload")
		}
	}
}

func cggmpTwoPartyKeygenSessions(t *testing.T) (*KeygenSession, []tss.Envelope, *KeygenSession, []tss.Envelope) {
	t.Helper()
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := startCGGMP21Keygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	session2, out2, err := startCGGMP21Keygen(tss.ThresholdConfig{
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

func exchangeKeygenCommitmentsForShares(t *testing.T, session1 *KeygenSession, out1 []tss.Envelope, session2 *KeygenSession, out2 []tss.Envelope) ([]tss.Envelope, []tss.Envelope) {
	t.Helper()
	tx1, err := session1.buildAcceptCGGMPKeygenCommitmentsTx(out2[0])
	if err != nil {
		t.Fatal(err)
	}
	effects1, err := tx1.apply(session1)
	if err != nil {
		t.Fatal(err)
	}
	tx1.markCommitted()
	tx2, err := session2.buildAcceptCGGMPKeygenCommitmentsTx(out1[0])
	if err != nil {
		t.Fatal(err)
	}
	effects2, err := tx2.apply(session2)
	if err != nil {
		t.Fatal(err)
	}
	tx2.markCommitted()
	return effects1.envelopes, effects2.envelopes
}

func installCGGMPKeygenShare(t *testing.T, session *KeygenSession, remoteOut []tss.Envelope) {
	t.Helper()
	shareEnv := mustCGGMPEnvelope(t, remoteOut, payloadKeygenShare, session.cfg.Self)
	shareTx, err := session.buildAcceptCGGMPKeygenShareTx(shareEnv)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.round1.recordShare(shareTx.from, shareTx.share, shareTx.factorProof); err != nil {
		t.Fatal(err)
	}
	shareTx.markCommitted()
}

func mustCGGMPEnvelope(t *testing.T, envelopes []tss.Envelope, payloadType tss.PayloadType, to tss.PartyID) tss.Envelope {
	t.Helper()
	for _, env := range envelopes {
		if env.PayloadType == payloadType && env.To == to {
			return env
		}
	}
	t.Fatalf("missing envelope type %q to %d", payloadType, to)
	return tss.Envelope{}
}
