package ed25519

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTKeygenProofDomainFixedDigest(t *testing.T) {
	t.Parallel()

	statement := testFROSTKeygenProofStatement(t)
	const want = "c8309787c6ef85807a911f2031a86d277e2eaa29b0f93551ecb0df53f795c531"
	if got := hex.EncodeToString(statement.domain()); got != want {
		t.Fatalf("keygen proof domain = %s, want %s", got, want)
	}
}

func TestFROSTKeygenProofDomainBindsEveryStatementField(t *testing.T) {
	t.Parallel()

	base := testFROSTKeygenProofStatement(t)
	baseline := base.domain()
	tests := []struct {
		name   string
		mutate func(*frostKeygenProofStatement)
	}{
		{name: "ciphersuite", mutate: func(s *frostKeygenProofStatement) { s.ciphersuite += "-changed" }},
		{name: "protocol", mutate: func(s *frostKeygenProofStatement) { s.protocol = tss.ProtocolCGGMP21Secp256k1 }},
		{name: "version", mutate: func(s *frostKeygenProofStatement) { s.version++ }},
		{name: "session", mutate: func(s *frostKeygenProofStatement) { s.sessionID[0] ^= 1 }},
		{name: "round", mutate: func(s *frostKeygenProofStatement) { s.round++ }},
		{name: "dealer", mutate: func(s *frostKeygenProofStatement) { s.dealer++ }},
		{name: "threshold", mutate: func(s *frostKeygenProofStatement) { s.threshold++ }},
		{name: "party set", mutate: func(s *frostKeygenProofStatement) { s.parties = tss.NewPartySet(1, 2, 4) }},
		{name: "plan hash", mutate: func(s *frostKeygenProofStatement) { s.planHash[0] ^= 1 }},
		{name: "coefficient commitment", mutate: func(s *frostKeygenProofStatement) { s.coefficientCommitment[1][0] ^= 1 }},
		{name: "chain-code commitment", mutate: func(s *frostKeygenProofStatement) { s.chainCodeCommitment[0] ^= 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			statement := cloneFROSTKeygenProofStatement(base)
			tc.mutate(&statement)
			if got := statement.domain(); bytes.Equal(got, baseline) {
				t.Fatal("keygen proof domain did not bind the substituted field")
			}
		})
	}

	reordered := cloneFROSTKeygenProofStatement(base)
	reordered.parties = tss.NewPartySet(3, 1, 2)
	if got := reordered.domain(); !bytes.Equal(got, baseline) {
		t.Fatalf("canonical party ordering changed proof domain: got %x want %x", got, baseline)
	}
}

func TestFROSTKeygenRogueConstantRejectedBeforeShareEffects(t *testing.T) {
	t.Parallel()

	session, remoteOut := frostKeygenTransitionSessions(t)
	defer session.Destroy()
	env := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)
	payload, err := unmarshalKeygenCommitmentsPayload(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	honestConstant, err := session.local.commitments.PointAt(0)
	if err != nil {
		t.Fatal(err)
	}
	// This is the classic 2-of-2 cancellation value C_rogue = -C_honest.
	// The attacker does not know its discrete logarithm, so retaining its proof
	// for a different constant must fail before any confidential share is sent.
	payload.Commitments.points[0] = fed.NewIdentityPoint().Negate(honestConstant)
	mutated, err := payload.MarshalBinaryWithLimits(session.limits)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = mutated

	out, err := session.Handle(testutil.DeliverEnvelope(env))
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if protocolErr.Party != env.From || protocolErr.Blame == nil {
		t.Fatalf("rogue constant rejection was not attributed to dealer %d: %#v", env.From, protocolErr)
	}
	if len(out) != 0 {
		t.Fatalf("rogue constant rejection emitted %d envelopes", len(out))
	}
	if !session.aborted || session.local != nil || session.pending != nil || session.keyShare != nil {
		t.Fatal("rogue constant rejection did not terminally abort and clear secret state")
	}
}

func TestFROSTKeygenVerifiesAllProofsBeforeShareEffects(t *testing.T) {
	t.Parallel()

	parties := tss.NewPartySet(1, 2, 3)
	sessionID := testutil.MustSessionID(9821)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	start := make(map[tss.PartyID][]tss.Envelope, len(parties))
	for _, party := range parties {
		session, out, err := startFROSTKeygen(tss.ThresholdConfig{
			Threshold: 2,
			Parties:   parties,
			Self:      party,
			SessionID: sessionID,
			Rand:      testutil.DeterministicReader(int64(9830 + party)),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Destroy()
		sessions[party] = session
		start[party] = out
	}
	target := sessions[1]
	if out, err := target.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, start[2], payloadKeygenCommitments, tss.BroadcastPartyId),
	)); err != nil || len(out) != 0 {
		t.Fatalf("first valid proof: out=%d err=%v", len(out), err)
	}
	if target.local == nil || len(target.local.polynomial) != target.cfg.Threshold {
		t.Fatal("local polynomial was destroyed before every R1 proof arrived")
	}

	last := mustFROSTEnvelope(t, start[3], payloadKeygenCommitments, tss.BroadcastPartyId)
	payload, err := unmarshalKeygenCommitmentsPayload(last.Payload)
	if err != nil {
		t.Fatal(err)
	}
	response, err := edcurve.ScalarFromCanonical(payload.Proof.Response)
	if err != nil {
		t.Fatal(err)
	}
	response.Add(response, edcurve.ScalarOne())
	payload.Proof.Response = response.Bytes()
	response.Set(fed.NewScalar())
	last.Payload, err = payload.MarshalBinaryWithLimits(target.limits)
	if err != nil {
		t.Fatal(err)
	}
	out, err := target.Handle(testutil.DeliverEnvelope(last))
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if len(out) != 0 {
		t.Fatalf("invalid final proof emitted %d confidential share effects", len(out))
	}
	if !target.aborted || target.local != nil {
		t.Fatal("invalid final proof did not terminally abort and clear polynomial material")
	}
}

func TestFROSTKeygenEarlyShareIsRevalidatedAtCommitmentCutover(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tamper  bool
		wantErr bool
	}{
		{name: "valid", tamper: false, wantErr: false},
		{name: "invalid", tamper: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, remoteOut := frostKeygenTransitionSessions(t)
			defer session.Destroy()
			share := mustFROSTEnvelope(t, remoteOut, payloadKeygenShare, session.cfg.Self)
			if tc.tamper {
				share = mutateCanonicalFROSTKeygenShare(t, session, share)
			}
			if out, err := session.Handle(testutil.DeliverEnvelope(share)); err != nil || len(out) != 0 {
				t.Fatalf("buffer early share: out=%d err=%v", len(out), err)
			}
			if session.state != keygenCollectingCommitments || session.round1.slots[share.From].share == nil {
				t.Fatal("early R2 share was not retained in its bounded sender slot")
			}

			commitment := mustFROSTEnvelope(t, remoteOut, payloadKeygenCommitments, tss.BroadcastPartyId)
			out, err := session.Handle(testutil.DeliverEnvelope(commitment))
			if !tc.wantErr {
				if err != nil {
					t.Fatal(err)
				}
				var sawShare, sawConfirmation bool
				for _, effect := range out {
					sawShare = sawShare || effect.PayloadType == payloadKeygenShare && effect.Round == keygenShareRound
					sawConfirmation = sawConfirmation || effect.PayloadType == payloadKeygenConfirmation && effect.Round == keygenConfirmationRound
				}
				if !sawShare || !sawConfirmation {
					t.Fatalf("valid buffered share effects missing R2/R3: %#v", out)
				}
				return
			}

			protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
			if protocolErr.Party != share.From || protocolErr.Blame == nil {
				t.Fatalf("invalid buffered share rejection = %#v", protocolErr)
			}
			if len(out) != 0 {
				t.Fatalf("invalid buffered share emitted %d effects at R1 cutover", len(out))
			}
			evidence, decodeErr := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			emptyPayloadHash := sha256.Sum256(nil)
			actualPayloadHash := sha256.Sum256(share.Payload)
			if evidence.Kind != tss.EvidenceKindFrostKeygenShare || !bytes.Equal(evidence.PayloadHash, emptyPayloadHash[:]) || bytes.Equal(evidence.PayloadHash, actualPayloadHash[:]) {
				t.Fatalf("confidential share evidence leaked or bound payload bytes: %#v", evidence)
			}
			if !session.aborted || session.local != nil || session.round1.slots[share.From].share != nil {
				t.Fatal("invalid buffered share did not terminally abort and clear secrets")
			}
		})
	}
}

func testFROSTKeygenProofStatement(t *testing.T) frostKeygenProofStatement {
	t.Helper()
	commitments, err := newKeygenCommitmentsFromPoints([]*fed.Point{
		fed.NewIdentityPoint().ScalarBaseMult(edcurve.ScalarFromUint64(7)),
		fed.NewIdentityPoint().ScalarBaseMult(edcurve.ScalarFromUint64(11)),
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tss.ThresholdConfig{
		Threshold: 2,
		Parties:   tss.NewPartySet(1, 2, 3),
		Self:      1,
		SessionID: testutil.MustSessionID(9811),
	}
	return newFROSTKeygenProofStatement(
		cfg,
		bytes.Repeat([]byte{0x33}, sha256.Size),
		2,
		commitments,
		bytes.Repeat([]byte{0x44}, sha256.Size),
	)
}

func cloneFROSTKeygenProofStatement(in frostKeygenProofStatement) frostKeygenProofStatement {
	out := in
	out.parties = in.parties.Clone()
	out.planHash = bytes.Clone(in.planHash)
	out.coefficientCommitment = make([][]byte, len(in.coefficientCommitment))
	for i := range in.coefficientCommitment {
		out.coefficientCommitment[i] = bytes.Clone(in.coefficientCommitment[i])
	}
	out.chainCodeCommitment = bytes.Clone(in.chainCodeCommitment)
	return out
}

func mutateCanonicalFROSTKeygenShare(t *testing.T, session *KeygenSession, env tss.Envelope) tss.Envelope {
	t.Helper()
	payload, err := unmarshalKeygenSharePayload(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Share.Destroy()
	share, err := edScalarFromSecret(payload.Share)
	if err != nil {
		t.Fatal(err)
	}
	share.Add(share, edcurve.ScalarOne())
	mutated, err := newEdSecretScalarFromFed(share)
	share.Set(fed.NewScalar())
	if err != nil {
		t.Fatal(err)
	}
	defer mutated.Destroy()
	payload.Share = mutated
	raw, err := payload.MarshalBinaryWithLimits(session.limits)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = raw
	return env
}
