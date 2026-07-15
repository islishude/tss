package ed25519

import (
	"bytes"
	"errors"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTSignGroupCommitmentIdentityAbortsWithoutBlameAndClearsState(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 2)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("identity group commitment"))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("identity group commitment"))
	if err != nil {
		t.Fatal(err)
	}
	dNonce := sign1.dNonce
	eNonce := sign1.eNonce
	if dNonce == nil || eNonce == nil {
		t.Fatal("active signing session did not retain its local nonces")
	}

	point := fed.NewGeneratorPoint()
	negated := fed.NewIdentityPoint().Negate(point)
	R, err := finalizeGroupCommitment([]*fed.Point{point, negated})
	if R != nil {
		t.Fatal("identity group commitment returned a point")
	}
	protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
	if protocolErr.Round != signStartRound || protocolErr.Party != tss.BroadcastPartyId || protocolErr.Blame != nil {
		t.Fatalf("identity group commitment attribution = round %d party %d blame %#v", protocolErr.Round, protocolErr.Party, protocolErr.Blame)
	}
	if !errors.Is(protocolErr.Err, errGroupNonceCommitmentIdentity) {
		t.Fatalf("identity group commitment error = %v", protocolErr.Err)
	}
	if !shouldAbortSession(err) {
		t.Fatal("identity group commitment was not classified as terminal")
	}

	// Use the same terminal-error hook as Handle. An identity group commitment is
	// a whole-transcript failure, so it aborts without attributing one signer.
	sign1.abortOnProtocolError(err)
	if !sign1.aborted || sign1.completed {
		t.Fatal("identity group commitment did not terminally abort signing")
	}
	if sign1.dNonce != nil || sign1.eNonce != nil || dNonce.FixedLen() != 0 || eNonce.FixedLen() != 0 {
		t.Fatal("identity group commitment retained local signing nonces")
	}
	if sign1.commitments != nil || sign1.commitMessage.Payload != nil {
		t.Fatal("identity group commitment retained nonce commitment state")
	}
	if len(sign1.partials) != 0 || len(sign1.pendingPartials) != 0 ||
		sign1.partialEnvelopes != nil || sign1.pendingEnvelopes != nil {
		t.Fatal("identity group commitment retained partial signature state")
	}
	if sign1.derivation != nil || sign1.message != nil || sign1.deltaScalar != nil {
		t.Fatal("identity group commitment retained signing intent secret state")
	}
	if _, ok := sign1.Signature(); ok {
		t.Fatal("identity group commitment exposed a signature")
	}
	if _, err := sign1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("aborted signing session accepted another commitment")
	} else {
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeAborted)
	}
}

func TestFROSTSignCommitmentPlanHashRejectDoesNotMutate(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.Parties)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("phase-02"), testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("phase-02"), testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[0]
	commitment, err := unmarshalNonceCommitmentPayload(bad.Payload)
	if err != nil {
		t.Fatal(err)
	}
	commitment.PlanHash = bytes.Repeat([]byte{0x42}, 32)
	bad.Payload, err = marshalNonceCommitmentPayload(commitment)
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotFROSTSignSession(sign1)
	out, err := sign1.Handle(testutil.DeliverEnvelope(bad))
	after := snapshotFROSTSignSession(sign1)

	if err == nil {
		t.Fatal("expected sign commitment plan hash mismatch to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected sign commitment produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignCommitmentBuildDoesNotMutate(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.Parties)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("phase-02-build"), testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("phase-02-build"), testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotFROSTSignSession(sign1)
	tx, err := sign1.buildSignTransition(testutil.DeliverEnvelope(out2[0]))
	after := snapshotFROSTSignSession(sign1)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.cleanupOnReject()
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignInvalidNonceCommitmentAbortsAndBlamesSender(t *testing.T) {
	t.Parallel()
	identity := make([]byte, 32)
	identity[0] = 1
	nonCanonicalIdentity := bytes.Clone(identity)
	nonCanonicalIdentity[len(nonCanonicalIdentity)-1] |= 0x80

	for _, tc := range []struct {
		name  string
		field string
		point []byte
	}{
		{name: "identity D", field: "D", point: identity},
		{name: "non-prime-order E", field: "E", point: make([]byte, 32)},
		{name: "non-canonical identity D", field: "D", point: nonCanonicalIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := frostKeygen(t, 2, 2)
			signers := tss.NewPartySet(1, 2)
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("invalid nonce commitment"))
			if err != nil {
				t.Fatal(err)
			}
			_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("invalid nonce commitment"))
			if err != nil {
				t.Fatal(err)
			}
			bad := out2[0]
			bad.Payload, err = testutil.RewriteWireFieldByName(
				bad.Payload,
				nonceCommitmentPayloadWireType,
				nonceCommitment{},
				tc.field,
				tc.point,
			)
			if err != nil {
				t.Fatal(err)
			}
			dNonce := sign1.dNonce
			eNonce := sign1.eNonce

			out, err := sign1.Handle(testutil.DeliverEnvelope(bad))
			protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
			if len(out) != 0 {
				t.Fatalf("invalid commitment produced %d outbound envelopes", len(out))
			}
			if protocolErr.Party != 2 || protocolErr.Blame == nil ||
				len(protocolErr.Blame.Parties) != 1 || protocolErr.Blame.Parties[0] != 2 {
				t.Fatalf("invalid commitment attribution = party %d blame %#v", protocolErr.Party, protocolErr.Blame)
			}
			evidence, err := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
			if err != nil {
				t.Fatalf("decode nonce commitment evidence: %v", err)
			}
			if evidence.Kind != tss.EvidenceKindFrostNonceCommitment || evidence.From != 2 {
				t.Fatalf("unexpected nonce commitment evidence kind=%q from=%d", evidence.Kind, evidence.From)
			}
			if !sign1.aborted || sign1.completed {
				t.Fatal("invalid commitment did not leave signing terminally aborted")
			}
			if sign1.dNonce != nil || sign1.eNonce != nil || dNonce.FixedLen() != 0 || eNonce.FixedLen() != 0 {
				t.Fatal("invalid commitment retained local signing nonces")
			}
			if sign1.derivation != nil || sign1.message != nil {
				t.Fatal("invalid commitment retained signing intent state")
			}
			_, err = sign1.Handle(testutil.DeliverEnvelope(out2[0]))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeAborted)
		})
	}
}

func TestFROSTSignLocalPartialPrepareFailureDoesNotCommit(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.Parties)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, []byte("phase-02"), testFROSTGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSign(shares[2], sessionID, signers, []byte("phase-02"), testFROSTGuard(2, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := unmarshalNonceCommitmentPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	sign1.commitments[2] = commitment
	sign1.planHash = []byte{0x01}

	before := snapshotFROSTSignSession(sign1)
	prepared, ok, err := sign1.prepareLocalPartial()
	after := snapshotFROSTSignSession(sign1)

	if err == nil {
		t.Fatal("expected local partial prepare to fail")
	}
	if ok || prepared != nil {
		t.Fatal("failed prepare returned a prepared partial")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignMalformedPartialAbortsAndClearsSecrets(t *testing.T) {
	t.Parallel()

	q := testEd25519ScalarEncodingLE(t, edcurve.Order(), 0)
	qPlusOne := testEd25519ScalarEncodingLE(t, edcurve.Order(), 1)
	highBitsSet := make([]byte, edcurve.ScalarSize)
	highBitsSet[len(highBitsSet)-1] = 0xe0

	for _, tc := range []struct {
		name    string
		payload []byte
		scalar  []byte
	}{
		{name: "malformed payload", payload: []byte("malformed partial")},
		{name: "z equals q", scalar: q},
		{name: "z equals q plus one", scalar: qPlusOne},
		{name: "scalar high three bits set", scalar: highBitsSet},
		{name: "short scalar", scalar: make([]byte, edcurve.ScalarSize-1)},
		{name: "long scalar", scalar: make([]byte, edcurve.ScalarSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := frostKeygen(t, 2, 3)
			parties := tss.SortParties(shares[1].state.Parties)
			signers := tss.NewPartySet(1, 2)
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			sign1, out1, err := startFROSTSign(
				shares[1], sessionID, signers, []byte("phase-02-malformed-partial"),
				testFROSTGuard(1, parties, sessionID),
			)
			if err != nil {
				t.Fatal(err)
			}
			sign2, out2, err := startFROSTSign(
				shares[2], sessionID, signers, []byte("phase-02-malformed-partial"),
				testFROSTGuard(2, parties, sessionID),
			)
			if err != nil {
				t.Fatal(err)
			}
			round2, err := sign2.Handle(testutil.DeliverEnvelope(out1[0]))
			if err != nil {
				t.Fatal(err)
			}
			if len(round2) != 1 || round2[0].PayloadType != payloadSignPartial {
				t.Fatalf("party 2 emitted %d round-2 envelopes", len(round2))
			}

			bad := round2[0]
			if tc.scalar != nil {
				bad.Payload, err = testutil.RewriteWireFieldByName(
					bad.Payload,
					signPartialPayloadWireType,
					signPartialPayload{},
					"Z",
					tc.scalar,
				)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				bad.Payload = bytes.Clone(tc.payload)
			}

			// Party 1 has not received party 2's commitment yet. Its nonces are
			// still live and it has not produced a local partial signature.
			dNonce := sign1.dNonce
			eNonce := sign1.eNonce
			if dNonce == nil || eNonce == nil || sign1.partialSent {
				t.Fatal("unexpected precondition before early round-2 delivery")
			}

			out, err := sign1.Handle(testutil.DeliverEnvelope(bad))
			protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
			if len(out) != 0 {
				t.Fatalf("invalid partial produced %d outbound envelopes", len(out))
			}
			if protocolErr.Party != 2 || protocolErr.Blame == nil ||
				len(protocolErr.Blame.Parties) != 1 || protocolErr.Blame.Parties[0] != 2 {
				t.Fatalf("invalid partial attribution = party %d blame %#v", protocolErr.Party, protocolErr.Blame)
			}
			evidence, err := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
			if err != nil {
				t.Fatalf("decode partial signature evidence: %v", err)
			}
			if evidence.Kind != tss.EvidenceKindFrostPartialSignature || evidence.From != 2 {
				t.Fatalf("unexpected partial evidence kind=%q from=%d", evidence.Kind, evidence.From)
			}
			if !sign1.aborted || sign1.completed {
				t.Fatal("invalid partial did not leave signing terminally aborted")
			}
			if sign1.dNonce != nil || sign1.eNonce != nil || dNonce.FixedLen() != 0 || eNonce.FixedLen() != 0 {
				t.Fatal("invalid partial retained local signing nonces")
			}
			if sign1.partialSent || len(sign1.partials) != 0 || len(sign1.pendingPartials) != 0 {
				t.Fatal("invalid partial produced or retained partial signature state")
			}
			if sign1.derivation != nil || sign1.message != nil {
				t.Fatal("invalid partial retained signing intent state")
			}
			if sign1.commitments != nil || sign1.commitMessage.Payload != nil {
				t.Fatal("invalid partial retained public nonce commitment state")
			}
			if _, ok := sign1.Signature(); ok {
				t.Fatal("aborted session exposed a signature")
			}
			_, err = sign1.Handle(testutil.DeliverEnvelope(out2[0]))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeAborted)
		})
	}
}

func TestFROSTSignPartialBuildDoesNotMutate(t *testing.T) {
	t.Parallel()

	signers := tss.NewPartySet(1, 2)
	sessions, round2 := frostSigningRound2(t, 2, 3, signers, []byte("phase-02-partial-build"))
	var partialFrom2 tss.Envelope
	for _, env := range round2 {
		if env.From == 2 {
			partialFrom2 = env
			break
		}
	}
	if partialFrom2.Payload == nil {
		t.Fatal("missing partial from party 2")
	}

	before := snapshotFROSTSignSession(sessions[1])
	tx, err := sessions[1].buildSignTransition(testutil.DeliverEnvelope(partialFrom2))
	after := snapshotFROSTSignSession(sessions[1])
	if err != nil {
		t.Fatal(err)
	}
	defer tx.cleanupOnReject()
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignInvalidPartialBuildDoesNotMutate(t *testing.T) {
	t.Parallel()

	signers := tss.NewPartySet(1, 2)
	sessions, round2 := frostSigningRound2(t, 2, 3, signers, []byte("phase-02-invalid-partial"))
	var partialFrom2 tss.Envelope
	for _, env := range round2 {
		if env.From == 2 {
			partialFrom2 = env
			break
		}
	}
	if partialFrom2.Payload == nil {
		t.Fatal("missing partial from party 2")
	}
	payload, err := unmarshalSignPartialPayload(partialFrom2.Payload)
	if err != nil {
		t.Fatal(err)
	}
	partialScalar := payload.Z.Scalar()
	defer partialScalar.Set(fed.NewScalar())
	badScalar := fed.NewScalar().Add(partialScalar, edcurve.ScalarOne())
	defer badScalar.Set(fed.NewScalar())
	badWire, err := newCanonicalScalar(badScalar)
	if err != nil {
		t.Fatal(err)
	}
	partialFrom2.Payload, err = marshalSignPartialPayload(signPartialPayload{
		Z:        badWire,
		PlanHash: payload.PlanHash,
	})
	if err != nil {
		t.Fatal(err)
	}

	before := snapshotFROSTSignSession(sessions[1])
	tx, err := sessions[1].buildAcceptPartialTx(partialFrom2)
	after := snapshotFROSTSignSession(sessions[1])
	if err == nil {
		if tx != nil {
			tx.cleanupOnReject()
		}
		t.Fatal("expected invalid partial to fail during transition build")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignAggregateFailureDoesNotCommit(t *testing.T) {
	t.Parallel()

	signers := tss.NewPartySet(1, 2)
	sessions, _ := frostSigningRound2(t, 2, 3, signers, []byte("phase-02"))
	session := sessions[1]
	session.partials[2] = fed.NewScalar()

	before := snapshotFROSTSignSession(session)
	err := session.tryAggregate()
	after := snapshotFROSTSignSession(session)

	if err == nil {
		t.Fatal("expected aggregate with invalid partial to fail")
	}
	assertFROSTSnapshotUnchanged(t, before, after)
}

func TestFROSTSignAggregateInvariantFailureDoesNotBlameSigners(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	round1 := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := startFROSTSign(shares[id], sessionID, signers, []byte("aggregate invariant"))
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		round1 = append(round1, out...)
	}

	// Corrupt only the local derived verification-key invariant, identically at
	// both signers. Per-signer partial equations still verify against the DKG
	// verification shares, but final Ed25519 verification must fail.
	wrongVerifyKey := fed.NewGeneratorPoint().Bytes()
	if bytes.Equal(wrongVerifyKey, shares[1].state.PublicKey.Bytes()) {
		wrongVerifyKey = fed.NewIdentityPoint().ScalarBaseMult(edcurve.ScalarFromUint64(2)).Bytes()
	}
	for _, session := range sessions {
		session.derivation.ChildPublicKey = bytes.Clone(wrongVerifyKey)
	}

	round2 := make([]tss.Envelope, 0, len(signers))
	for _, env := range round1 {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			round2 = append(round2, out...)
		}
	}
	var partialFrom2 tss.Envelope
	for _, env := range round2 {
		if env.From == 2 {
			partialFrom2 = env
			break
		}
	}
	if partialFrom2.Payload == nil {
		t.Fatal("missing partial from party 2")
	}

	out, err := sessions[1].Handle(testutil.DeliverEnvelope(partialFrom2))
	protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeInvariant)
	if len(out) != 0 {
		t.Fatalf("aggregate invariant failure produced %d outbound envelopes", len(out))
	}
	if protocolErr.Party != tss.BroadcastPartyId || protocolErr.Blame != nil {
		t.Fatalf("aggregate invariant failure was attributed: party=%d blame=%#v", protocolErr.Party, protocolErr.Blame)
	}
	if tss.IsAttributableError(err) {
		t.Fatal("aggregate invariant failure was classified as attributable")
	}
	if !sessions[1].aborted || sessions[1].completed {
		t.Fatal("aggregate invariant failure did not abort the signing session")
	}
	if len(sessions[1].partials) != 0 || sessions[1].derivation != nil || sessions[1].message != nil {
		t.Fatal("aggregate invariant failure retained signing state")
	}
}
