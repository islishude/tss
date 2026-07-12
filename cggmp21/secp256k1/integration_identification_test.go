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

func TestThresholdECDSAOnlineIdentificationInvariantFallback(t *testing.T) {
	t.Parallel()
	shares := identificationKeyShares(t)
	signers := tss.NewPartySet(1, 2)
	presigns := identificationPresigns(t, shares, signers)
	for _, party := range signers {
		if got := len(presigns[party].state.sigmaOpenings); got != len(signers)-1 {
			t.Fatalf("party %d retained %d sigma openings, want %d", party, got, len(signers)-1)
		}
		if opening := presigns[party].state.sigmaOpenings[0]; opening.Peer == party || opening.Opening == nil {
			t.Fatalf("party %d retained invalid sigma opening for peer %d", party, opening.Peer)
		}
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := SignRequest{Context: testPresignContext(), Message: []byte("online identification")}
	s1, out1, err := startCGGMP21Sign(shares[1], presigns[1], sessionID, request)
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startCGGMP21Sign(shares[2], presigns[2], sessionID, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []*SignSession{s1, s2} {
		got := len(session.presign.state.sigmaOpenings)
		if got != len(signers)-1 {
			t.Fatalf("sign session %d retained %d sigma openings, want %d", session.key.state.Party, got, len(signers)-1)
		}
		if session.presign.state.sigmaOpenings[0].Opening == nil {
			t.Fatalf("sign session %d retained destroyed sigma opening", session.key.state.Party)
		}
	}

	wrongPublic, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarOne()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrongPublic, s1.publicKey) {
		wrongPublic, err = secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(2)))
		if err != nil {
			t.Fatal(err)
		}
	}
	s1.publicKey = bytes.Clone(wrongPublic)
	s2.publicKey = bytes.Clone(wrongPublic)

	idFrom1, err := s2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	idFrom2, err := s1.Handle(testutil.DeliverEnvelope(out2[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Identifying() || !s2.Identifying() || s1.Completed() || s2.Completed() {
		t.Fatal("aggregate signature alert did not remain in identification")
	}
	if signature, ok := s1.Signature(); ok || signature != nil {
		t.Fatal("identifying session exposed a signature")
	}
	if len(idFrom1) != 1 || len(idFrom2) != 1 || idFrom1[0].PayloadType != payloadSignIdentification || idFrom2[0].PayloadType != payloadSignIdentification {
		t.Fatal("missing online identification payload")
	}

	bad := idFrom2[0].Clone()
	badPayload, err := tss.DecodeBinaryValueWithLimits[signIdentificationPayload](bad.Payload, s2.limits)
	if err != nil {
		t.Fatal(err)
	}
	badPayload.MulProofs[0].Proof.TranscriptHash[0] ^= 1
	bad.Payload, err = badPayload.MarshalBinaryWithLimits(s2.limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s2.Handle(testutil.DeliverEnvelope(bad))
	var badProofErr *tss.ProtocolError
	if !errors.As(err, &badProofErr) || badProofErr.Code != tss.ErrCodeVerification || badProofErr.Blame == nil {
		t.Fatalf("invalid sign identification proof = %v, want blamed verification error", err)
	}
	evidence, err := tss.DecodeBinary[tss.BlameEvidence](badProofErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := evidence.Field(tss.IdentificationRecordEvidenceKey); !ok {
		t.Fatal("invalid sign identification proof omitted IdentificationRecord")
	}

	_, err = s1.Handle(testutil.DeliverEnvelope(idFrom1[0]))
	var invariant *tss.ProtocolError
	if !errors.As(err, &invariant) || invariant.Code != tss.ErrCodeInvariant || invariant.Blame != nil {
		t.Fatalf("all-valid sign identification fallback = %v, want unblamed invariant", err)
	}
	if s1.Identifying() || !s1.aborted {
		t.Fatal("all-valid sign identification fallback did not enter terminal state")
	}
	if len(presigns[1].state.sigmaOpenings) != 0 || len(presigns[1].state.SigmaOpeningRecords) != 0 {
		t.Fatal("all-valid sign identification fallback retained sigma openings")
	}
}

func TestThresholdECDSAPresignPersistsSigmaOpeningsWithoutRestoringReuse(t *testing.T) {
	t.Parallel()
	shares := identificationKeyShares(t)
	signers := tss.NewPartySet(1, 2)
	presigns := identificationPresigns(t, shares, signers)
	presign := presigns[1]
	if len(presign.state.sigmaOpenings) != 1 || len(presign.state.SigmaOpeningRecords) != 1 {
		t.Fatal("completed presign omitted sigma identification witness records")
	}
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !IsPresignConsumed(presign) {
		t.Fatal("serializing private presign did not consume the live handle")
	}
	var restored Presign
	if err := restored.UnmarshalBinaryWithLimits(raw, testLimits()); err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	if len(restored.state.SigmaOpeningRecords) != 1 {
		t.Fatal("restored private presign omitted persisted sigma opening record")
	}
	if len(restored.state.sigmaOpenings) != 0 {
		t.Fatal("serialization restored reusable sigma witness handles")
	}
	if !IsPresignConsumed(&restored) {
		t.Fatal("restored presign was reusable")
	}
}

func TestThresholdECDSAPresignIdentificationInvariantFallback(t *testing.T) {
	t.Parallel()
	shares := identificationKeyShares(t)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)
	s1, out1, err := startIdentificationPresign(shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startIdentificationPresign(shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}

	round2From1 := deliverPresignMessagesTo(t, s1, 1, out2)
	round2From2 := deliverPresignMessagesTo(t, s2, 2, out1)
	round3From2, err := s2.Handle(testutil.DeliverEnvelope(round2From1[0]))
	if err != nil {
		t.Fatal(err)
	}
	round3From1, err := s1.Handle(testutil.DeliverEnvelope(round2From2[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(round3From1) != 1 || len(round3From2) != 1 {
		t.Fatalf("round3 output cardinality = %d/%d, want 1/1", len(round3From1), len(round3From2))
	}

	// Corrupt only each party's private completion state after its valid Round 3
	// proof was generated. Every public identification proof remains valid, so
	// the conditional round must end in an unblamed local invariant.
	for _, session := range []*PresignSession{s1, s2} {
		current, err := secpScalarFromSecret(session.presign.state.ChiShare)
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := secpSecretScalarFromScalar(secp.ScalarAdd(current, secp.ScalarOne()))
		if err != nil {
			t.Fatal(err)
		}
		session.presign.state.ChiShare.Destroy()
		session.presign.state.ChiShare = replacement
	}

	idFrom2, err := s1.Handle(testutil.DeliverEnvelope(round3From2[0]))
	if err != nil {
		t.Fatal(err)
	}
	idFrom1, err := s2.Handle(testutil.DeliverEnvelope(round3From1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Identifying() || !s2.Identifying() {
		t.Fatal("presign aggregate alert did not enter identification")
	}
	if s1.Completed() || s2.Completed() {
		t.Fatal("identifying presign reported completion")
	}
	if presign, ok := s1.Presign(); ok || presign != nil {
		t.Fatal("identifying session exposed a presign")
	}
	if len(idFrom1) != 1 || len(idFrom2) != 1 || idFrom1[0].PayloadType != payloadPresignIdentification || idFrom2[0].PayloadType != payloadPresignIdentification {
		t.Fatalf("identification output cardinality/type mismatch")
	}
	bad := idFrom2[0].Clone()
	badPayload, err := tss.DecodeBinaryValueWithLimits[presignIdentificationPayload](bad.Payload, s2.limits)
	if err != nil {
		t.Fatal(err)
	}
	badPayload.MulProof.TranscriptHash[0] ^= 1
	bad.Payload, err = badPayload.MarshalBinaryWithLimits(s2.limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s2.Handle(testutil.DeliverEnvelope(bad))
	var badProofErr *tss.ProtocolError
	if !errors.As(err, &badProofErr) || badProofErr.Code != tss.ErrCodeVerification || badProofErr.Blame == nil {
		t.Fatalf("invalid identification proof = %v, want blamed verification error", err)
	}
	evidence, err := tss.DecodeBinary[tss.BlameEvidence](badProofErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, ok := evidence.Field(tss.IdentificationRecordEvidenceKey)
	if !ok {
		t.Fatal("invalid identification proof evidence omitted IdentificationRecord")
	}
	var record tss.IdentificationRecord
	if err := record.UnmarshalBinary(recordBytes); err != nil {
		t.Fatal(err)
	}
	if record.Accused != 1 || record.FailureClass != "presign-identification-invalid-proof" {
		t.Fatalf("unexpected identification record: accused=%d class=%q", record.Accused, record.FailureClass)
	}

	_, err = s1.Handle(testutil.DeliverEnvelope(idFrom1[0]))
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeInvariant || protocolErr.Blame != nil {
		t.Fatalf("all-valid identification fallback = %v, want unblamed invariant", err)
	}
	if s1.Identifying() || !s1.aborted {
		t.Fatal("all-valid presign identification fallback did not enter terminal state")
	}
	if s1.startOpening != nil || s1.gammaOpening != nil || s1.paillier != nil {
		t.Fatal("all-valid presign identification fallback retained identification witnesses")
	}
}

func identificationKeyShares(t testing.TB) map[tss.PartyID]*KeyShare {
	t.Helper()
	params := testSecurityParams()
	// Πdec for online identification proves a ciphertext containing an
	// EllPrime affine value multiplied by an Ell-bit ECDSA scalar. The ordinary
	// 768-bit fast fixture is intentionally too small to rule out plaintext
	// wraparound for that exceptional path.
	params.MinPaillierBits = 1024
	return secpKeygenWithPlanOption(t, 2, 2, KeygenPlanOption{Limits: testLimitsPtr(), SecurityParams: &params})
}

func startIdentificationPresign(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet) (*PresignSession, []tss.Envelope, error) {
	plan, err := NewPresignPlan(PresignPlanOption{
		Key: key, SessionID: sessionID, Signers: signers, Context: testPresignContext(), Limits: testLimitsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	guard := testCGGMP21Guard(key.state.Party, key.state.Parties, sessionID)
	return StartPresign(key, plan, tss.LocalConfig{Self: key.state.Party}, guard)
}

func identificationPresigns(t testing.TB, shares map[tss.PartyID]*KeyShare, signers tss.PartySet) map[tss.PartyID]*Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*PresignSession, len(signers))
	queue := make([]tss.Envelope, 0)
	for _, party := range signers {
		session, out, err := startIdentificationPresign(shares[party], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, party := range signers {
			if party == env.From || (env.To != tss.BroadcastPartyId && env.To != party) {
				continue
			}
			out, err := sessions[party].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	result := make(map[tss.PartyID]*Presign, len(signers))
	for _, party := range signers {
		presign, ok := sessions[party].Presign()
		if !ok {
			t.Fatalf("identification presign did not complete for party %d", party)
		}
		result[party] = presign
	}
	return result
}
