package ed25519

import (
	"bytes"
	"crypto/sha256"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/zk/schnorred25519"
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

func TestFROSTKeygenInvalidChainCodeCommitRejectAbortsAndClearsSecrets(t *testing.T) {
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

	out, err := session.Handle(testutil.DeliverEnvelope(bad))
	if err == nil {
		t.Fatal("expected invalid chain-code commitment to be rejected")
	}
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if protocolErr.Party != bad.From || protocolErr.Blame == nil {
		t.Fatalf("malformed public commitment missing attributable evidence: %#v", protocolErr)
	}
	evidence, decodeErr := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
	if decodeErr != nil || evidence.Kind != tss.EvidenceKindFrostKeygenCommitment {
		t.Fatalf("malformed public commitment evidence kind: evidence=%#v err=%v", evidence, decodeErr)
	}
	publicPayloadHash := sha256.Sum256(bad.Payload)
	if !bytes.Equal(evidence.PayloadHash, publicPayloadHash[:]) {
		t.Fatalf("public commitment evidence payload hash = %x, want actual envelope payload hash %x", evidence.PayloadHash, publicPayloadHash)
	}
	if len(out) != 0 {
		t.Fatalf("rejected commitment produced %d outbound envelopes", len(out))
	}
	if !session.aborted || session.state != keygenAborted || session.local != nil || session.pending != nil || session.keyShare != nil {
		t.Fatal("malformed public commitment did not terminally abort and clear secret state")
	}
}

func TestFROSTKeygenRound2ConstructionFailureIsTerminalInvariant(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	session.local.DestroyPolynomial()
	commitment := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)

	out, err := session.Handle(testutil.DeliverEnvelope(commitment))
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeInvariant)
	if protocolErr.Party != tss.BroadcastPartyId || protocolErr.Blame != nil {
		t.Fatalf("round-2 construction invariant attribution = %#v", protocolErr)
	}
	if len(out) != 0 {
		t.Fatalf("round-2 construction invariant emitted %d effects", len(out))
	}
	if !session.aborted || session.local != nil || session.pending != nil || session.keyShare != nil {
		t.Fatal("round-2 construction invariant did not abort and clear secret state")
	}
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
	out1, out2 = exchangeFROSTKeygenCommitments(t, session1, out1, session2, out2)
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
	out1, out2 = exchangeFROSTKeygenCommitments(t, session1, out1, session2, out2)
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

func TestFROSTKeygenEarlyInvalidConfirmationClearsUnexposedRound3Effect(t *testing.T) {
	t.Run("Handle aborts without effects", func(t *testing.T) {
		session, remoteShare := frostKeygenEarlyInvalidConfirmationFixture(t)

		out, err := session.Handle(testutil.DeliverEnvelope(remoteShare))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
		if len(out) != 0 {
			t.Fatalf("invalid early confirmation emitted %d outbound effects", len(out))
		}
		assertFROSTKeygenAbortClearedChainCodeReveals(t, session)
	})

	t.Run("staged envelope backing is cleared", func(t *testing.T) {
		session, remoteShare := frostKeygenEarlyInvalidConfirmationFixture(t)
		payload, err := unmarshalKeygenSharePayload(remoteShare.Payload)
		if err != nil {
			t.Fatal(err)
		}
		slot, err := session.round1.slot(remoteShare.From)
		if err != nil {
			payload.Share.Destroy()
			t.Fatal(err)
		}
		slot.share = payload.Share

		snap, ok, err := session.round1.snapshot()
		if err != nil || !ok {
			t.Fatalf("complete keygen share snapshot: ok=%v err=%v", ok, err)
		}
		defer snap.Destroy()
		prepared, err := session.preparePendingKeyMaterial(snap)
		if err != nil {
			t.Fatal(err)
		}
		unexposedPayloadBacking := prepared.env.Payload
		if len(unexposedPayloadBacking) == 0 || testutil.IsZeroBytes(unexposedPayloadBacking) {
			prepared.destroy()
			t.Fatal("prepared round-3 envelope has no chain-code reveal payload")
		}

		out, err := session.commitPreparedPendingKeyShare(prepared)
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
		if len(out) != 0 {
			t.Fatalf("failed staged round-3 commit emitted %d effects", len(out))
		}
		if !testutil.IsZeroBytes(unexposedPayloadBacking) {
			t.Fatal("failed staged round-3 commit retained the unexposed envelope payload")
		}

		confirmationRevealBacking := session.confirmations.confirmations[session.cfg.Self].ChainCode
		inboxRevealBacking := session.confirmations.chainCodes[session.cfg.Self]
		pendingRevealBacking := session.pending.localChainCode
		if !shouldAbortSession(err) {
			t.Fatalf("invalid early confirmation was not terminal: %v", err)
		}
		session.abort()
		for name, reveal := range map[string][]byte{
			"confirmation": confirmationRevealBacking,
			"inbox":        inboxRevealBacking,
			"pending":      pendingRevealBacking,
		} {
			if !testutil.IsZeroBytes(reveal) {
				t.Fatalf("abort retained %s chain-code reveal backing bytes", name)
			}
		}
		assertFROSTKeygenAbortClearedChainCodeReveals(t, session)
	})
}

func frostKeygenEarlyInvalidConfirmationFixture(t *testing.T) (*KeygenSession, tss.Envelope) {
	t.Helper()

	session1, out1, session2, out2 := frostTwoPartyKeygenSessions(t)
	t.Cleanup(session1.Destroy)
	t.Cleanup(session2.Destroy)
	t.Cleanup(func() {
		clearEnvelopePayloads(out1)
		clearEnvelopePayloads(out2)
	})

	round2From1, err := session1.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, out2, payloadKeygenCommitments, tss.BroadcastPartyId),
	))
	if err != nil {
		t.Fatal(err)
	}
	round2From2, err := session2.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, out1, payloadKeygenCommitments, tss.BroadcastPartyId),
	))
	if err != nil {
		clearEnvelopePayloads(round2From1)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clearEnvelopePayloads(round2From1)
		clearEnvelopePayloads(round2From2)
	})

	remoteConfirmationOut, err := session2.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, round2From1, payloadKeygenShare, session2.cfg.Self),
	))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clearEnvelopePayloads(remoteConfirmationOut) })
	remoteConfirmation := mustFROSTEnvelope(t, remoteConfirmationOut, payloadKeygenConfirmation, tss.BroadcastPartyId)
	decoded, err := tss.DecodeBinary[KeygenConfirmation](remoteConfirmation.Payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(decoded.ChainCode)
	decoded.TranscriptHash[0] ^= 1
	remoteConfirmation.Payload, err = decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(remoteConfirmation.Payload) })

	if out, err := session1.Handle(testutil.DeliverEnvelope(remoteConfirmation)); err != nil {
		t.Fatalf("buffer invalid early confirmation: %v", err)
	} else if len(out) != 0 {
		clearEnvelopePayloads(out)
		t.Fatalf("invalid early confirmation produced %d effects before the share round completed", len(out))
	}
	if session1.aborted || session1.pending != nil || session1.confirmations.confirmations[session2.cfg.Self] == nil {
		t.Fatal("invalid early confirmation was not retained for full round-3 validation")
	}
	return session1, mustFROSTEnvelope(t, round2From2, payloadKeygenShare, session1.cfg.Self)
}

func assertFROSTKeygenAbortClearedChainCodeReveals(t *testing.T, session *KeygenSession) {
	t.Helper()
	if !session.aborted || session.completed || session.state != keygenAborted {
		t.Fatal("invalid early confirmation did not terminally abort keygen")
	}
	if session.local != nil || session.pending != nil || session.keyShare != nil {
		t.Fatal("aborted keygen retained local or pending key material")
	}
	if len(session.confirmations.chainCodes) != 0 || len(session.confirmations.confirmations) != 0 || len(session.pendingConfirmations) != 0 {
		t.Fatal("aborted keygen retained chain-code reveal state")
	}
	for _, slot := range session.round1.slots {
		if slot.share != nil {
			t.Fatal("aborted keygen retained a confidential share")
		}
	}
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
			} else if !tc.commitmentFirst && len(out) != 0 {
				t.Fatalf("first aggregate-identity input produced %d outbound envelopes", len(out))
			} else if tc.commitmentFirst {
				assertOnlyFROSTKeygenShares(t, out)
				clearEnvelopePayloads(out)
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

func TestFROSTKeygenIdentityVerificationShareAbortsAndClearsSecrets(t *testing.T) {
	for i, commitmentFirst := range []bool{true, false} {
		name := "share arrives last"
		if !commitmentFirst {
			name = "commitment arrives last"
		}
		t.Run(name, func(t *testing.T) {
			parties := tss.NewPartySet(1, 2)
			sessionID := testutil.MustSessionID(int64(870 + i))
			session, _, err := startFROSTKeygen(tss.ThresholdConfig{
				Threshold: 2,
				Parties:   parties,
				Self:      1,
				SessionID: sessionID,
				Rand:      testutil.DeterministicReader(int64(880 + i)),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Destroy()

			commitment, share := maliciousFROSTIdentityVerificationShareEnvelopes(t, session, 2)
			first, last := share, commitment
			if commitmentFirst {
				first, last = commitment, share
			}
			if out, err := session.Handle(testutil.DeliverEnvelope(first)); err != nil {
				t.Fatalf("first verification-identity input rejected early: %v", err)
			} else if !commitmentFirst && len(out) != 0 {
				t.Fatalf("first verification-identity input produced %d outbound envelopes", len(out))
			} else if commitmentFirst {
				assertOnlyFROSTKeygenShares(t, out)
				clearEnvelopePayloads(out)
			}

			out, err := session.Handle(testutil.DeliverEnvelope(last))
			protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
			if protocolErr.Blame != nil || protocolErr.Party != tss.BroadcastPartyId {
				t.Fatalf("aggregate verification identity was attributed to one dealer: %#v", protocolErr)
			}
			if len(out) != 0 {
				t.Fatalf("aggregate verification identity produced %d outbound envelopes", len(out))
			}
			if !session.aborted || session.completed || session.state != keygenAborted {
				t.Fatal("aggregate verification identity did not leave keygen terminally aborted")
			}
			if session.local != nil || session.pending != nil || session.keyShare != nil {
				t.Fatal("aggregate verification identity retained local or assembled secret material")
			}
			for _, slot := range session.round1.slots {
				if slot.share != nil {
					t.Fatal("aggregate verification identity retained a round-1 secret share slot")
				}
			}
		})
	}
}

func maliciousFROSTIdentityVerificationShareEnvelopes(t *testing.T, session *KeygenSession, dealer tss.PartyID) (tss.Envelope, tss.Envelope) {
	t.Helper()
	if session.local == nil || session.local.commitments == nil || session.local.localShare == nil {
		t.Fatal("missing local material for verification-identity fixture")
	}

	honestShare, err := edScalarFromSecret(session.local.localShare)
	if err != nil {
		t.Fatal(err)
	}
	defer honestShare.Set(fed.NewScalar())
	remoteShare := fed.NewScalar().Subtract(fed.NewScalar(), honestShare)
	defer remoteShare.Set(fed.NewScalar())

	honestConstant, err := session.local.commitments.PointAt(0)
	if err != nil {
		t.Fatal(err)
	}
	constantScalar := edcurve.ScalarOne()
	defer constantScalar.Set(fed.NewScalar())
	constantCommitment := fed.NewIdentityPoint().ScalarBaseMult(constantScalar)
	if fed.NewIdentityPoint().Add(honestConstant, constantCommitment).Equal(fed.NewIdentityPoint()) == 1 {
		constantScalar.Add(constantScalar, edcurve.ScalarOne())
		constantCommitment = fed.NewIdentityPoint().ScalarBaseMult(constantScalar)
	}
	remoteEvaluation := fed.NewIdentityPoint().ScalarBaseMult(remoteShare)
	linearCommitment := fed.NewIdentityPoint().Subtract(remoteEvaluation, constantCommitment)
	commitments, err := newKeygenCommitmentsFromPoints(
		[]*fed.Point{constantCommitment, linearCommitment},
		session.cfg.Threshold,
	)
	if err != nil {
		t.Fatal(err)
	}

	chainCode := bytes.Repeat([]byte{0x6a}, 32)
	t.Cleanup(func() { clear(chainCode) })
	chainCodeCommitment := bip32util.ChainCodeCommitment(frostChainCodeCommitLabel, session.cfg.SessionID, dealer, chainCode)
	commitPayload, err := (keygenCommitmentsPayload{
		Commitments:     commitments,
		ChainCodeCommit: chainCodeCommitment,
		PlanHash:        bytes.Clone(session.planHash),
		Proof:           mustFROSTKeygenProof(t, session, dealer, commitments, chainCodeCommitment, constantScalar),
	}).MarshalBinaryWithLimits(session.limits)
	if err != nil {
		t.Fatal(err)
	}
	commitmentEnvelope, err := newEnvelope(session.cfg, keygenStartRound, dealer, tss.BroadcastPartyId, payloadKeygenCommitments, commitPayload)
	clear(commitPayload)
	if err != nil {
		t.Fatal(err)
	}

	secretShare, err := newEdSecretScalarFromFed(remoteShare)
	if err != nil {
		t.Fatal(err)
	}
	sharePayload, err := (keygenSharePayload{
		Share:    secretShare,
		PlanHash: bytes.Clone(session.planHash),
	}).MarshalBinaryWithLimits(session.limits)
	secretShare.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	shareEnvelope, err := newEnvelope(session.cfg, keygenShareRound, dealer, session.cfg.Self, payloadKeygenShare, sharePayload)
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

func maliciousFROSTIdentityAggregateEnvelopes(t *testing.T, session *KeygenSession, dealer tss.PartyID) (tss.Envelope, tss.Envelope) {
	t.Helper()
	if session.local == nil || session.local.commitments == nil {
		t.Fatal("missing local commitments for aggregate-identity fixture")
	}
	honestConstant, err := session.local.commitments.PointAt(0)
	if err != nil {
		t.Fatal(err)
	}
	constantScalar := fed.NewScalar().Negate(session.local.polynomial[0])
	defer constantScalar.Set(fed.NewScalar())
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
	chainCodeCommitment := bip32util.ChainCodeCommitment(frostChainCodeCommitLabel, session.cfg.SessionID, dealer, chainCode)
	commitPayload, err := (keygenCommitmentsPayload{
		Commitments:     commitments,
		ChainCodeCommit: chainCodeCommitment,
		PlanHash:        bytes.Clone(session.planHash),
		Proof:           mustFROSTKeygenProof(t, session, dealer, commitments, chainCodeCommitment, constantScalar),
	}).MarshalBinaryWithLimits(session.limits)
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
	sharePayload, err := (keygenSharePayload{
		Share:    secretShare,
		PlanHash: bytes.Clone(session.planHash),
	}).MarshalBinaryWithLimits(session.limits)
	secretShare.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	shareEnvelope, err := newEnvelope(session.cfg, keygenShareRound, dealer, session.cfg.Self, payloadKeygenShare, sharePayload)
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
	session1, out1, session2, out2 := frostTwoPartyKeygenSessions(t)
	remoteRound2, err := session2.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, out1, payloadKeygenCommitments, tss.BroadcastPartyId),
	))
	if err != nil {
		session1.Destroy()
		session2.Destroy()
		t.Fatal(err)
	}
	session2.Destroy()
	return session1, append(out2, remoteRound2...)
}

func exchangeFROSTKeygenCommitments(
	t *testing.T,
	session1 *KeygenSession,
	out1 []tss.Envelope,
	session2 *KeygenSession,
	out2 []tss.Envelope,
) ([]tss.Envelope, []tss.Envelope) {
	t.Helper()
	round2From1, err := session1.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, out2, payloadKeygenCommitments, tss.BroadcastPartyId),
	))
	if err != nil {
		t.Fatal(err)
	}
	round2From2, err := session2.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, out1, payloadKeygenCommitments, tss.BroadcastPartyId),
	))
	if err != nil {
		t.Fatal(err)
	}
	return append(out1, round2From1...), append(out2, round2From2...)
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
	slot.proof = commitment.Proof.Clone()
	slot.share = share.Share
}

func mustFROSTKeygenProof(
	t *testing.T,
	session *KeygenSession,
	dealer tss.PartyID,
	commitments keygenCommitments,
	chainCodeCommitment []byte,
	constant *fed.Scalar,
) *schnorred25519.Proof {
	t.Helper()
	constantSecret, err := newEdSecretScalarFromFed(constant)
	if err != nil {
		t.Fatal(err)
	}
	defer constantSecret.Destroy()
	constantPoint, err := commitments.PointAt(0)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := schnorred25519.Prepare(testutil.DeterministicReader(int64(9700+dealer)), constantPoint.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer preparation.Destroy()
	proof, err := preparation.Finalize(
		frostKeygenProofDomain(session.cfg, session.planHash, dealer, commitments, chainCodeCommitment),
		constantSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func structurallyValidFROSTKeygenProof() *schnorred25519.Proof {
	response := edcurve.ScalarOne()
	defer response.Set(fed.NewScalar())
	return &schnorred25519.Proof{
		Commitment: fed.NewGeneratorPoint().Bytes(),
		Response:   response.Bytes(),
	}
}

func assertOnlyFROSTKeygenShares(t *testing.T, out []tss.Envelope) {
	t.Helper()
	if len(out) == 0 {
		t.Fatal("completed keygen commitment round emitted no confidential shares")
	}
	for _, env := range out {
		if env.Round != keygenShareRound || env.PayloadType != payloadKeygenShare || env.To == tss.BroadcastPartyId {
			t.Fatalf("unexpected keygen round-2 effect: %#v", env)
		}
	}
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
