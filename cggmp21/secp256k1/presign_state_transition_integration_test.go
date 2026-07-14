//go:build integration

package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

type failingPresignEnvelopeSigner struct{}

func (failingPresignEnvelopeSigner) SignEnvelopeDigest([32]byte) ([]byte, error) {
	return nil, errors.New("injected presign envelope signing failure")
}

func TestCGGMP21PresignRound1PlanHashRejectDoesNotMutate(t *testing.T) {
	s1, _, s2, out2 := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	bad := out2[0]
	payload, err := unmarshalPresignRound1Payload(bad.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PlanHash = bytes.Repeat([]byte{0x42}, 32)
	bad.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPPresignSession(s1)
	tx, err := s1.buildAcceptPresignRound1PayloadTx(bad)
	after := snapshotCGGMPPresignSession(s1)
	if err == nil {
		if tx != nil {
			tx.cleanupOnReject()
		}
		t.Fatal("expected round1 plan hash mismatch")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRound1DeferredVerificationFailureDoesNotAcceptPayload(t *testing.T) {
	s1, _, s2, out2 := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	proofEnv := mustPresignEnvelope(t, out2, payloadPresignRound1Proof, s1.key.state.Party)
	proof, err := unmarshalPresignRound1ProofPayload(proofEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	proof.PublicRound1Hash = bytes.Repeat([]byte{0x7a}, 32)
	proofEnv.Payload, err = marshalPresignRound1ProofPayload(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofTx, err := s1.buildAcceptPresignRound1ProofTx(proofEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proofTx.apply(s1); err != nil {
		t.Fatal(err)
	}
	proofTx.markCommitted()

	before := snapshotCGGMPPresignSession(s1)
	payloadTx, err := s1.buildAcceptPresignRound1PayloadTx(out2[0])
	after := snapshotCGGMPPresignSession(s1)
	if err == nil {
		if payloadTx != nil {
			payloadTx.cleanupOnReject()
		}
		t.Fatal("expected deferred round1 proof verification failure")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRound2MalformedRejectDoesNotMutate(t *testing.T) {
	s1, _, s2, _ := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	bad, err := newEnvelope(s1.config, 2, 2, 1, payloadPresignRound2, []byte("malformed round2"))
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPPresignSession(s1)
	out, err := s1.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotCGGMPPresignSession(s1)
	if err == nil {
		t.Fatal("expected malformed round2 payload to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected round2 payload produced %d envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRound2VerificationFailureDoesNotWriteAlphaShares(t *testing.T) {
	s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	installPresignRound1Peer(t, s1, out2)
	installPresignRound1Peer(t, s2, out1)
	prepared2, ok, err := s2.preparePresignRound2Outputs()
	if err != nil || !ok {
		t.Fatalf("prepare party 2 round2: ok=%v err=%v", ok, err)
	}
	defer prepared2.destroy()
	effects := s2.commitPresignRound2Outputs(prepared2)
	round2 := mustPresignEnvelope(t, effects.envelopes, payloadPresignRound2, s1.key.state.Party)
	payload, err := unmarshalPresignRound2Payload(round2.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Round1Echo = bytes.Repeat([]byte{0x51}, 32)
	round2.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPPresignSession(s1)
	tx, err := s1.buildAcceptPresignRound2Tx(round2)
	after := snapshotCGGMPPresignSession(s1)
	if err == nil {
		if tx != nil {
			tx.cleanupOnReject()
		}
		t.Fatal("expected round2 echo mismatch")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRound2PrepareFailureDoesNotWriteBetaShares(t *testing.T) {
	s1, _, s2, out2 := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	installPresignRound1Peer(t, s1, out2)
	s1.planHash = []byte{0x01}

	before := snapshotCGGMPPresignSession(s1)
	prepared, ok, err := s1.preparePresignRound2Outputs()
	after := snapshotCGGMPPresignSession(s1)
	if prepared != nil {
		prepared.destroy()
	}
	if err == nil {
		t.Fatal("expected round2 preparation to fail with invalid plan hash")
	}
	if ok {
		t.Fatal("failed round2 preparation reported ready")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRound3MalformedRejectDoesNotMutate(t *testing.T) {
	s1, _, s2, _ := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	bad, err := newEnvelope(s1.config, 3, 2, tss.BroadcastPartyId, payloadPresignRound3, []byte("malformed round3"))
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPPresignSession(s1)
	out, err := s1.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotCGGMPPresignSession(s1)
	if err == nil {
		t.Fatal("expected malformed round3 payload to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected round3 payload produced %d envelopes", len(out))
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignRound3PrepareDoesNotMutateAndDestroysStagedSecrets(t *testing.T) {
	s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()
	installPresignRound1Peer(t, s1, out2)
	installPresignRound1Peer(t, s2, out1)
	if !bytes.Equal(s1.round1Echo(), s2.round1Echo()) {
		if s1.sessionID != s2.sessionID {
			t.Fatal("round1 session IDs differ")
		}
		if !bytes.Equal(s1.planHash, s2.planHash) {
			t.Fatal("round1 plan hashes differ")
		}
		if !bytes.Equal(s1.contextHash, s2.contextHash) {
			t.Fatal("round1 context hashes differ")
		}
		if !bytes.Equal(s1.derivation.AdditiveShift, s2.derivation.AdditiveShift) {
			t.Fatal("round1 derivation shifts differ")
		}
		for _, id := range s1.signers {
			left, _ := s1.partyState(id)
			right, _ := s2.partyState(id)
			leftPayload, err := left.round1.payload.MarshalBinaryWithLimits(s1.limits)
			if err != nil {
				t.Fatal(err)
			}
			rightPayload, err := right.round1.payload.MarshalBinaryWithLimits(s2.limits)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(leftPayload, rightPayload) {
				t.Fatalf("Figure 8 round1 payload differs for party %d", id)
			}
		}
		t.Fatal("round1 echoes differ without a field mismatch")
	}

	prepared1, ok, err := s1.preparePresignRound2Outputs()
	if err != nil || !ok {
		t.Fatalf("prepare party 1 round2: ok=%v err=%v", ok, err)
	}
	defer prepared1.destroy()
	s1.commitPresignRound2Outputs(prepared1)

	prepared2, ok, err := s2.preparePresignRound2Outputs()
	if err != nil || !ok {
		t.Fatalf("prepare party 2 round2: ok=%v err=%v", ok, err)
	}
	defer prepared2.destroy()
	effects2 := s2.commitPresignRound2Outputs(prepared2)
	round2From2 := mustPresignEnvelope(t, effects2.envelopes, payloadPresignRound2, s1.key.state.Party)
	round2Tx, err := s1.buildAcceptPresignRound2Tx(round2From2)
	if err != nil {
		t.Fatal(err)
	}
	installPresignRound2Tx(t, s1, round2Tx)

	before := snapshotCGGMPPresignSession(s1)
	prepared3, ok, err := s1.preparePresignRound3Output()
	after := snapshotCGGMPPresignSession(s1)
	if err != nil || !ok {
		t.Fatalf("prepare party 1 round3: ok=%v err=%v", ok, err)
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
	stagedDelta := prepared3.payload.Delta
	stagedChi := prepared3.chi
	prepared3.destroy()
	if !testutil.IsZeroBytes(stagedDelta.FixedBytes()) ||
		!testutil.IsZeroBytes(stagedChi.FixedBytes()) {
		t.Fatal("destroying prepared round3 output did not clear staged Figure 8 secrets")
	}
}

func TestCGGMP21PresignRound3VerificationFailureDoesNotWriteCommitment(t *testing.T) {
	s1, s2, _, round3From2 := presignSessionsWithRound3Outputs(t)
	defer s1.Destroy()
	defer s2.Destroy()
	payload, err := unmarshalPresignRound3Payload(round3From2.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.DeltaPoint = testCurvePointBytes(t, 7)
	round3From2.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	payload.Delta.Destroy()
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotCGGMPPresignSession(s1)
	tx, err := s1.buildAcceptPresignRound3Tx(round3From2)
	after := snapshotCGGMPPresignSession(s1)
	if err == nil {
		if tx != nil {
			tx.cleanupOnReject()
		}
		t.Fatal("expected Figure 8 Elog proof verification failure")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignCompletionPrepareDoesNotMutateAndDestroysFinalPresign(t *testing.T) {
	s1, s2, _, round3From2 := presignSessionsWithRound3Outputs(t)
	defer s1.Destroy()
	defer s2.Destroy()
	tx, err := s1.buildAcceptPresignRound3Tx(round3From2)
	if err != nil {
		t.Fatal(err)
	}
	installPresignRound3Tx(t, s1, tx)

	before := snapshotCGGMPPresignSession(s1)
	prepared, ok, err := s1.maybePreparePresignCompletion()
	after := snapshotCGGMPPresignSession(s1)
	if err != nil || !ok {
		t.Fatalf("prepare final presign: ok=%v err=%v", ok, err)
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
	stagedK := prepared.presign.state.KShare
	stagedChi := prepared.presign.state.ChiShare
	stagedCommitment := prepared.presign.state.Commitments[0].DeltaTilde
	prepared.destroy()
	if !testutil.IsZeroBytes(stagedK.FixedBytes()) ||
		!testutil.IsZeroBytes(stagedChi.FixedBytes()) ||
		!testutil.IsZeroBytes(stagedCommitment) {
		t.Fatal("destroying prepared completion did not clear final presign secrets")
	}
}

func TestCGGMP21AggregateZeroAbortsWithoutBlameAndDestroysSecrets(t *testing.T) {
	s1, s2, _, round3From2 := presignSessionsWithRound3Outputs(t)
	defer s1.Destroy()
	defer s2.Destroy()

	self, ok := s1.partyState(s1.key.state.Party)
	if !ok {
		t.Fatal("missing local Figure 8 state")
	}
	selfDelta, err := secpScalarFromSecretAllowZero(self.round3.delta)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalPresignRound3Payload(round3From2.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Delta.Destroy()
	payload.Delta, err = secpSecretScalarFromScalarAllowZero(secp.ScalarNeg(selfDelta))
	if err != nil {
		payload.Proof.Destroy()
		t.Fatal(err)
	}
	round3From2.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	payload.Delta.Destroy()
	payload.Proof.Destroy()
	if err != nil {
		t.Fatal(err)
	}

	kShare := s1.kShare
	gamma := s1.gamma
	xBar := s1.xBar
	out, err := s1.Handle(testutil.DeliverEnvelope(round3From2))
	if len(out) != 0 {
		t.Fatalf("aggregate-zero failure emitted %d envelopes", len(out))
	}
	if !errors.Is(err, errUnattributedPresignFailure) {
		t.Fatalf("aggregate-zero failure = %v, want errUnattributedPresignFailure", err)
	}
	var protocolErr *tss.ProtocolError
	if errors.As(err, &protocolErr) && protocolErr.Blame != nil {
		t.Fatalf("aggregate-zero failure carried blame: %#v", protocolErr.Blame)
	}
	if !s1.aborted || !s1.leaseFinished || s1.completed || s1.identifying {
		t.Fatalf("aggregate-zero terminal state = aborted:%v leaseFinished:%v completed:%v identifying:%v",
			s1.aborted, s1.leaseFinished, s1.completed, s1.identifying)
	}
	if s1.kShare != nil || s1.gamma != nil || s1.xBar != nil || s1.paillier != nil || len(s1.parties) != 0 {
		t.Fatal("aggregate-zero abort retained secret session state")
	}
	if !testutil.IsZeroBytes(kShare.FixedBytes()) || !testutil.IsZeroBytes(gamma.FixedBytes()) || !testutil.IsZeroBytes(xBar.FixedBytes()) {
		t.Fatal("aggregate-zero abort did not destroy retained scalar witnesses")
	}
	if _, ok := s1.Presign(); ok {
		t.Fatal("aggregate-zero abort exposed a persisted presign")
	}
}

func TestCGGMP21PreparedPresignStartDestroyClearsOwnedState(t *testing.T) {
	s1, out1, s2, _ := cggmpTwoPartyPresignSessions(t)
	s2.Destroy()
	ownedOut := tss.CloneSlice(out1)
	kShare := s1.kShare
	gamma := s1.gamma
	xBar := s1.xBar
	paillierP := s1.paillier.P
	prepared := &preparedPresignStart{
		session: s1,
		out:     ownedOut,
	}
	prepared.destroy()

	if !s1.aborted || s1.paillier != nil {
		t.Fatal("destroyed prepared presign start retained live session resources")
	}
	if !testutil.IsZeroBytes(kShare.FixedBytes()) ||
		!testutil.IsZeroBytes(gamma.FixedBytes()) ||
		!testutil.IsZeroBytes(xBar.FixedBytes()) ||
		!testutil.IsZeroBytes(paillierP.FixedBytes()) {
		t.Fatal("destroyed prepared presign start did not clear local secrets")
	}
	for _, env := range ownedOut {
		if !testutil.IsZeroBytes(env.Payload) {
			t.Fatal("destroyed prepared presign start retained outbound payload")
		}
	}
}

func TestCGGMP21PresignReadinessDerivesFromPartyState(t *testing.T) {
	s := &PresignSession{
		key: &KeyShare{state: &keyShareState{Party: 1}},
		parties: []presignPartyState{
			{id: 1},
			{id: 2},
		},
	}
	s.parties[0].round1.havePayload = true
	s.parties[0].round1.verified = true
	s.parties[1].round1.havePayload = true
	s.parties[1].round1.haveProof = true
	s.parties[1].round1.verified = true
	if !s.allRound1PayloadsAccepted() || !s.allRound1ProofsAccepted() || !s.allRound1Verified() {
		t.Fatal("complete round1 party state was not ready")
	}

	s.parties[1].round2.havePayload = true
	if !s.allRound2Accepted() {
		t.Fatal("complete round2 party state was not ready")
	}
	for i := range s.parties {
		s.parties[i].round3.havePayload = true
	}
	if !s.allRound3Accepted() {
		t.Fatal("complete round3 party state was not ready")
	}
}

func TestCGGMP21PresignEarlyRoundReadinessIsTypedAndDoesNotMutate(t *testing.T) {
	s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
	defer s1.Destroy()
	defer s2.Destroy()

	var round2From2 tss.Envelope
	for _, env := range out1 {
		if env.To != tss.BroadcastPartyId && env.To != s2.key.state.Party {
			continue
		}
		out, err := s2.Handle(testutil.DeliverEnvelope(env))
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range out {
			if candidate.PayloadType == payloadPresignRound2 && candidate.To == s1.key.state.Party {
				round2From2 = candidate
			}
		}
	}
	if round2From2.PayloadType == "" {
		t.Fatal("missing party 2 round2 output")
	}

	before := snapshotCGGMPPresignSession(s1)
	err := s1.validatePresignInboundReadiness(round2From2)
	after := snapshotCGGMPPresignSession(s1)
	var protocolErr *tss.ProtocolError
	var earlyErr *presignEarlyMessageError
	if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeRound || !errors.As(err, &earlyErr) {
		t.Fatalf("early round2 error = %v", err)
	}
	assertCGGMPSnapshotUnchanged(t, before, after)

	for _, env := range out2 {
		if env.To != tss.BroadcastPartyId && env.To != s1.key.state.Party {
			continue
		}
		if _, err := s1.Handle(testutil.DeliverEnvelope(env)); err != nil {
			t.Fatal(err)
		}
	}
	peerState, ok := s1.partyState(2)
	if !ok || peerState.round2.outboundEnvelope.PayloadType != payloadPresignRound2 {
		t.Fatal("missing party 1 round2 output")
	}
	round2From1 := peerState.round2.outboundEnvelope.Clone()
	round3From2, err := s2.Handle(testutil.DeliverEnvelope(round2From1))
	if err != nil {
		t.Fatal(err)
	}
	round3 := mustPresignEnvelope(t, round3From2, payloadPresignRound3, tss.BroadcastPartyId)

	before = snapshotCGGMPPresignSession(s1)
	err = s1.validatePresignInboundReadiness(round3)
	after = snapshotCGGMPPresignSession(s1)
	protocolErr = nil
	earlyErr = nil
	if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeRound || !errors.As(err, &earlyErr) {
		t.Fatalf("early round3 error = %v", err)
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21PresignTransitionPreparationFailureDoesNotAcceptInbound(t *testing.T) {
	t.Run("round1_to_round2", func(t *testing.T) {
		s1, _, s2, out2 := cggmpTwoPartyPresignSessions(t)
		defer s1.Destroy()
		defer s2.Destroy()
		proofEnv := mustPresignEnvelope(t, out2, payloadPresignRound1Proof, s1.key.state.Party)
		proofTx, err := s1.buildAcceptPresignRound1ProofTx(proofEnv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := proofTx.apply(s1); err != nil {
			t.Fatal(err)
		}
		proofTx.markCommitted()
		s1.config.EnvelopeSigner = failingPresignEnvelopeSigner{}

		before := snapshotCGGMPPresignSession(s1)
		tx, err := s1.buildAcceptPresignRound1PayloadTx(out2[0])
		after := snapshotCGGMPPresignSession(s1)
		if tx != nil {
			tx.cleanupOnReject()
		}
		if err == nil {
			t.Fatal("expected injected round2 envelope construction failure")
		}
		assertCGGMPSnapshotUnchanged(t, before, after)
	})

	t.Run("round2_to_round3", func(t *testing.T) {
		s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
		defer s1.Destroy()
		defer s2.Destroy()
		installPresignRound1Peer(t, s1, out2)
		installPresignRound1Peer(t, s2, out1)
		prepared1, ok, err := s1.preparePresignRound2Outputs()
		if err != nil || !ok {
			t.Fatalf("prepare party 1 round2: ok=%v err=%v", ok, err)
		}
		s1.commitPresignRound2Outputs(prepared1)
		prepared2, ok, err := s2.preparePresignRound2Outputs()
		if err != nil || !ok {
			t.Fatalf("prepare party 2 round2: ok=%v err=%v", ok, err)
		}
		effects2 := s2.commitPresignRound2Outputs(prepared2)
		round2 := mustPresignEnvelope(t, effects2.envelopes, payloadPresignRound2, s1.key.state.Party)
		s1.config.EnvelopeSigner = failingPresignEnvelopeSigner{}

		before := snapshotCGGMPPresignSession(s1)
		tx, err := s1.buildAcceptPresignRound2Tx(round2)
		after := snapshotCGGMPPresignSession(s1)
		if tx != nil {
			tx.cleanupOnReject()
		}
		if err == nil {
			t.Fatal("expected injected round3 envelope construction failure")
		}
		assertCGGMPSnapshotUnchanged(t, before, after)
	})

	t.Run("round3_to_red_alert", func(t *testing.T) {
		s1, s2, _, round3From2 := presignSessionsWithRound3Outputs(t)
		defer s1.Destroy()
		defer s2.Destroy()
		self, ok := s1.partyState(s1.key.state.Party)
		if !ok || self.round3.delta == nil {
			t.Fatal("missing local Figure 8 round3 state")
		}
		originalDelta := self.round3.delta
		originalScalar, err := secpScalarFromSecretAllowZero(originalDelta)
		if err != nil {
			t.Fatal(err)
		}
		replacementScalar := secp.ScalarAdd(originalScalar, secp.ScalarOne())
		if replacementScalar.IsZero() {
			replacementScalar = secp.ScalarOne()
		}
		replacement, err := secpSecretScalarFromScalar(replacementScalar)
		if err != nil {
			t.Fatal(err)
		}
		self.round3.delta = replacement
		defer func() {
			self.round3.delta = originalDelta
			replacement.Destroy()
		}()
		s1.config.EnvelopeSigner = failingPresignEnvelopeSigner{}

		before := snapshotCGGMPPresignSession(s1)
		tx, err := s1.buildAcceptPresignRound3Tx(round3From2)
		after := snapshotCGGMPPresignSession(s1)
		if tx != nil {
			tx.cleanupOnReject()
		}
		if err == nil {
			t.Fatal("expected injected Figure 9 red-alert envelope construction failure")
		}
		if s1.identifying || s1.redAlertKind != "" || len(s1.redAlertDigest) != 0 || len(s1.redAlertPayloads) != 0 {
			t.Fatal("failed Figure 9 red-alert preparation mutated session state")
		}
		assertCGGMPSnapshotUnchanged(t, before, after)
	})
}

func TestCGGMP21PresignEarlyEnvelopeCanBeRetriedAfterPrerequisites(t *testing.T) {
	t.Run("round2_before_round1", func(t *testing.T) {
		s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
		defer s1.Destroy()
		defer s2.Destroy()
		var round2From2 tss.Envelope
		for _, env := range out1 {
			if env.To != tss.BroadcastPartyId && env.To != s2.key.state.Party {
				continue
			}
			out, err := s2.Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range out {
				if candidate.PayloadType == payloadPresignRound2 && candidate.To == s1.key.state.Party {
					round2From2 = candidate
				}
			}
		}
		if round2From2.PayloadType == "" {
			t.Fatal("missing party 2 round2 output")
		}

		before := snapshotCGGMPPresignSession(s1)
		out, err := s1.Handle(testutil.DeliverEnvelope(round2From2))
		after := snapshotCGGMPPresignSession(s1)
		var protocolErr *tss.ProtocolError
		var earlyErr *presignEarlyMessageError
		if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeRound || protocolErr.Blame != nil ||
			!errors.As(err, &earlyErr) || len(out) != 0 || s1.aborted {
			t.Fatalf("early round2 = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
		assertCGGMPSnapshotUnchanged(t, before, after)

		for _, env := range out2 {
			if env.To != tss.BroadcastPartyId && env.To != s1.key.state.Party {
				continue
			}
			if _, err := s1.Handle(testutil.DeliverEnvelope(env)); err != nil {
				t.Fatal(err)
			}
		}
		out, err = s1.Handle(testutil.DeliverEnvelope(round2From2))
		if err != nil || len(out) == 0 || s1.aborted {
			t.Fatalf("round2 retry = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
		state, ok := s1.partyState(round2From2.From)
		if !ok || !state.round2.havePayload || state.mta.alphaDelta == nil || state.mta.alphaSigma == nil {
			t.Fatal("round2 retry did not commit verified MtA state")
		}
	})

	t.Run("round3_before_all_round2", func(t *testing.T) {
		s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
		defer s1.Destroy()
		defer s2.Destroy()
		var round2From1, round2From2 tss.Envelope
		for _, env := range out2 {
			if env.To != tss.BroadcastPartyId && env.To != s1.key.state.Party {
				continue
			}
			out, err := s1.Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range out {
				if candidate.PayloadType == payloadPresignRound2 && candidate.To == s2.key.state.Party {
					round2From1 = candidate
				}
			}
		}
		for _, env := range out1 {
			if env.To != tss.BroadcastPartyId && env.To != s2.key.state.Party {
				continue
			}
			out, err := s2.Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range out {
				if candidate.PayloadType == payloadPresignRound2 && candidate.To == s1.key.state.Party {
					round2From2 = candidate
				}
			}
		}
		if round2From1.PayloadType == "" || round2From2.PayloadType == "" {
			t.Fatal("missing round2 output")
		}
		round3Out, err := s2.Handle(testutil.DeliverEnvelope(round2From1))
		if err != nil {
			t.Fatal(err)
		}
		round3From2 := mustPresignEnvelope(t, round3Out, payloadPresignRound3, tss.BroadcastPartyId)

		before := snapshotCGGMPPresignSession(s1)
		out, err := s1.Handle(testutil.DeliverEnvelope(round3From2))
		after := snapshotCGGMPPresignSession(s1)
		var protocolErr *tss.ProtocolError
		var earlyErr *presignEarlyMessageError
		if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeRound || protocolErr.Blame != nil ||
			!errors.As(err, &earlyErr) || len(out) != 0 || s1.aborted {
			t.Fatalf("early round3 = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
		assertCGGMPSnapshotUnchanged(t, before, after)

		if _, err := s1.Handle(testutil.DeliverEnvelope(round2From2)); err != nil {
			t.Fatal(err)
		}
		out, err = s1.Handle(testutil.DeliverEnvelope(round3From2))
		if err != nil || len(out) != 0 || !s1.completed || s1.aborted {
			t.Fatalf("round3 retry = out:%d err:%v completed:%v aborted:%v", len(out), err, s1.completed, s1.aborted)
		}
	})
}

func TestCGGMP21PresignOutputFailureLeavesEnvelopeRetryable(t *testing.T) {
	t.Run("round1_to_round2", func(t *testing.T) {
		s1, _, s2, out2 := cggmpTwoPartyPresignSessions(t)
		defer s1.Destroy()
		defer s2.Destroy()
		proof := mustPresignEnvelope(t, out2, payloadPresignRound1Proof, s1.key.state.Party)
		if _, err := s1.Handle(testutil.DeliverEnvelope(proof)); err != nil {
			t.Fatal(err)
		}
		originalSigner := s1.config.EnvelopeSigner
		s1.config.EnvelopeSigner = failingPresignEnvelopeSigner{}
		before := snapshotCGGMPPresignSession(s1)
		out, err := s1.Handle(testutil.DeliverEnvelope(out2[0]))
		after := snapshotCGGMPPresignSession(s1)
		if err == nil || len(out) != 0 || s1.aborted {
			t.Fatalf("injected round2 failure = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
		assertCGGMPSnapshotUnchanged(t, before, after)

		s1.config.EnvelopeSigner = originalSigner
		out, err = s1.Handle(testutil.DeliverEnvelope(out2[0]))
		if err != nil || len(out) == 0 || s1.aborted {
			t.Fatalf("round1 retry = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
	})

	t.Run("round2_to_round3", func(t *testing.T) {
		s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
		defer s1.Destroy()
		defer s2.Destroy()
		var round2From2 tss.Envelope
		for _, env := range out2 {
			if env.To != tss.BroadcastPartyId && env.To != s1.key.state.Party {
				continue
			}
			if _, err := s1.Handle(testutil.DeliverEnvelope(env)); err != nil {
				t.Fatal(err)
			}
		}
		for _, env := range out1 {
			if env.To != tss.BroadcastPartyId && env.To != s2.key.state.Party {
				continue
			}
			out, err := s2.Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range out {
				if candidate.PayloadType == payloadPresignRound2 && candidate.To == s1.key.state.Party {
					round2From2 = candidate
				}
			}
		}
		if round2From2.PayloadType == "" {
			t.Fatal("missing party 2 round2 output")
		}
		originalSigner := s1.config.EnvelopeSigner
		s1.config.EnvelopeSigner = failingPresignEnvelopeSigner{}
		before := snapshotCGGMPPresignSession(s1)
		out, err := s1.Handle(testutil.DeliverEnvelope(round2From2))
		after := snapshotCGGMPPresignSession(s1)
		if err == nil || len(out) != 0 || s1.aborted {
			t.Fatalf("injected round3 failure = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
		assertCGGMPSnapshotUnchanged(t, before, after)

		s1.config.EnvelopeSigner = originalSigner
		out, err = s1.Handle(testutil.DeliverEnvelope(round2From2))
		if err != nil || len(out) == 0 || s1.aborted {
			t.Fatalf("round2 retry = out:%d err:%v aborted:%v", len(out), err, s1.aborted)
		}
	})
}

func cggmpTwoPartyPresignSessions(t *testing.T) (*PresignSession, []tss.Envelope, *PresignSession, []tss.Envelope) {
	t.Helper()
	h := newHarness(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := startTestPresign(h.shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startTestPresign(h.shares[2], sessionID, signers)
	if err != nil {
		s1.Destroy()
		t.Fatal(err)
	}
	return s1, out1, s2, out2
}

func installPresignRound1Peer(t *testing.T, session *PresignSession, remoteOut []tss.Envelope) {
	t.Helper()
	publicEnv := mustPresignEnvelope(t, remoteOut, payloadPresignRound1, tss.BroadcastPartyId)
	public, err := unmarshalPresignRound1Payload(publicEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	proofEnv := mustPresignEnvelope(t, remoteOut, payloadPresignRound1Proof, session.key.state.Party)
	proof, err := unmarshalPresignRound1ProofPayload(proofEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.validateRound1Public(publicEnv.From, public); err != nil {
		t.Fatal(err)
	}
	if err := session.validateRound1Proof(publicEnv.From, public, proof); err != nil {
		t.Fatal(err)
	}
	st, ok := session.partyState(publicEnv.From)
	if !ok {
		t.Fatal("missing peer state")
	}
	st.round1.payload = public
	st.round1.havePayload = true
	st.round1.proof = proof
	st.round1.proofEnvelope = proofEnv.Clone()
	st.round1.haveProof = true
	st.round1.verified = true
}

func installPresignRound2Tx(t *testing.T, session *PresignSession, tx *acceptPresignRound2Tx) {
	t.Helper()
	tx.prepared.destroy()
	tx.prepared = preparedPresignTransitionEffects{}
	st, ok := session.partyState(tx.from)
	if !ok {
		t.Fatal("missing round2 peer state")
	}
	st.round2.payload = tx.payload
	st.round2.payloadEnvelope = tx.envelope.Clone()
	st.round2.havePayload = true
	st.mta.alphaDelta = tx.material.alphaDelta
	st.mta.alphaSigma = tx.material.alphaSigma
	tx.markCommitted()
}

func installPresignRound3Tx(t *testing.T, session *PresignSession, tx *acceptPresignRound3Tx) {
	t.Helper()
	tx.prepared.destroy()
	tx.prepared = preparedPresignTransitionEffects{}
	st, ok := session.partyState(tx.from)
	if !ok {
		t.Fatal("missing round3 peer state")
	}
	st.round3 = presignRound3State{
		delta:       tx.payload.Delta,
		deltaPoint:  tx.payload.DeltaPoint,
		sPoint:      tx.payload.S,
		proof:       tx.payload.Proof,
		havePayload: true,
	}
	tx.markCommitted()
}

func presignSessionsWithRound3Outputs(t *testing.T) (*PresignSession, *PresignSession, tss.Envelope, tss.Envelope) {
	t.Helper()
	s1, out1, s2, out2 := cggmpTwoPartyPresignSessions(t)
	installPresignRound1Peer(t, s1, out2)
	installPresignRound1Peer(t, s2, out1)

	prepared1, ok, err := s1.preparePresignRound2Outputs()
	if err != nil || !ok {
		s1.Destroy()
		s2.Destroy()
		t.Fatalf("prepare party 1 round2: ok=%v err=%v", ok, err)
	}
	effects1 := s1.commitPresignRound2Outputs(prepared1)
	prepared2, ok, err := s2.preparePresignRound2Outputs()
	if err != nil || !ok {
		s1.Destroy()
		s2.Destroy()
		t.Fatalf("prepare party 2 round2: ok=%v err=%v", ok, err)
	}
	effects2 := s2.commitPresignRound2Outputs(prepared2)

	round2From1 := mustPresignEnvelope(t, effects1.envelopes, payloadPresignRound2, s2.key.state.Party)
	tx1, err := s2.buildAcceptPresignRound2Tx(round2From1)
	if err != nil {
		s1.Destroy()
		s2.Destroy()
		t.Fatal(err)
	}
	installPresignRound2Tx(t, s2, tx1)
	round2From2 := mustPresignEnvelope(t, effects2.envelopes, payloadPresignRound2, s1.key.state.Party)
	tx2, err := s1.buildAcceptPresignRound2Tx(round2From2)
	if err != nil {
		s1.Destroy()
		s2.Destroy()
		t.Fatal(err)
	}
	installPresignRound2Tx(t, s1, tx2)

	prepared3For1, ok, err := s1.preparePresignRound3Output()
	if err != nil || !ok {
		s1.Destroy()
		s2.Destroy()
		t.Fatalf("prepare party 1 round3: ok=%v err=%v", ok, err)
	}
	effects3For1, err := s1.commitPresignRound3Output(prepared3For1)
	if err != nil {
		s1.Destroy()
		s2.Destroy()
		t.Fatal(err)
	}
	prepared3For2, ok, err := s2.preparePresignRound3Output()
	if err != nil || !ok {
		s1.Destroy()
		s2.Destroy()
		t.Fatalf("prepare party 2 round3: ok=%v err=%v", ok, err)
	}
	effects3For2, err := s2.commitPresignRound3Output(prepared3For2)
	if err != nil {
		s1.Destroy()
		s2.Destroy()
		t.Fatal(err)
	}
	return s1, s2,
		mustPresignEnvelope(t, effects3For1.envelopes, payloadPresignRound3, tss.BroadcastPartyId),
		mustPresignEnvelope(t, effects3For2.envelopes, payloadPresignRound3, tss.BroadcastPartyId)
}

func mustPresignEnvelope(t *testing.T, envelopes []tss.Envelope, payloadType tss.PayloadType, to tss.PartyID) tss.Envelope {
	t.Helper()
	for _, env := range envelopes {
		if env.PayloadType == payloadType && env.To == to {
			return env
		}
	}
	t.Fatalf("missing presign envelope type %q to %d", payloadType, to)
	return tss.Envelope{}
}
