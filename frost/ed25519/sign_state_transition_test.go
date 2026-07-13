package ed25519

import (
	"bytes"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

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
	nonCanonicalIdentity := append([]byte(nil), identity...)
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

func TestFROSTSignMalformedPartialRejectDoesNotMutate(t *testing.T) {
	t.Parallel()

	signers := tss.NewPartySet(1, 2)
	sessions, round2 := frostSigningRound2(t, 2, 3, signers, []byte("phase-02-malformed-partial"))
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
	partialFrom2.Payload = []byte("malformed partial")

	before := snapshotFROSTSignSession(sessions[1])
	out, err := sessions[1].Handle(testutil.DeliverEnvelope(partialFrom2))
	after := snapshotFROSTSignSession(sessions[1])
	if err == nil {
		t.Fatal("expected malformed partial to be rejected")
	}
	if len(out) != 0 {
		t.Fatalf("rejected partial produced %d outbound envelopes", len(out))
	}
	assertFROSTSnapshotUnchanged(t, before, after)
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
