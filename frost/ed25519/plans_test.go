package ed25519

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTKeygenPlanDigestBindsGlobalIntentAndCopies(t *testing.T) {
	t.Parallel()

	sessionID := frostPlanTestSession(0x11)
	parties := []tss.PartyID{3, 1, 2}
	plan, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: []tss.PartyID{1, 2, 3}, Threshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSamePlanDigest(t, plan, same)

	parties[0] = 99
	gotParties := plan.Parties()
	gotParties[0] = 99
	if !bytes.Equal(partyIDsBytes(plan.Parties()), partyIDsBytes([]tss.PartyID{1, 2, 3})) {
		t.Fatal("keygen plan party getter or constructor aliases caller memory")
	}
	localLimits := DefaultLimits()
	localLimits.Payload.MaxMessageBytes--
	withLocalLimits, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: []tss.PartyID{1, 2, 3}, Threshold: 2, Limits: &localLimits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSamePlanDigest(t, plan, withLocalLimits)

	for name, other := range map[string]*KeygenPlan{
		"threshold": mustFROSTKeygenPlan(t, sessionID, []tss.PartyID{1, 2, 3}, 3),
		"session":   mustFROSTKeygenPlan(t, frostPlanTestSession(0x12), []tss.PartyID{1, 2, 3}, 2),
	} {
		assertDifferentPlanDigest(t, name, plan, other)
	}
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: []tss.PartyID{1, 2}, Threshold: 3,
	}); err == nil {
		t.Fatal("keygen plan accepted threshold greater than party count")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
	strictLimits := DefaultLimits()
	strictLimits.Threshold.MaxParties = 2
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: []tss.PartyID{1, 2, 3}, Threshold: 2, Limits: &strictLimits,
	}); err == nil {
		t.Fatal("keygen plan ignored local party limit")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
}

func TestFROSTKeygenPlanZeroValueIsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := new(KeygenPlan).Digest(); err == nil {
		t.Fatal("zero-value keygen plan produced a digest")
	}
	if _, _, err := StartKeygen(nil, tss.LocalConfig{Self: 1}, nil); err == nil {
		t.Fatal("nil keygen plan started a session")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
}

func TestFROSTSignPlanDigestBindsKeyMetadataAndCopies(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID := frostPlanTestSession(0x21)
	signers := []tss.PartyID{2, 1}
	message := []byte("plan-bound message")

	limits := testLimits()
	plan, err := NewSignPlan(SignPlanOption{
		Key: shares[1], SessionID: sessionID, Signers: signers, Context: testFROSTSigningContext(), Message: message, Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewSignPlan(SignPlanOption{
		Key: shares[2], SessionID: sessionID, Signers: []tss.PartyID{1, 2}, Context: testFROSTSigningContext(), Message: message, Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSamePlanDigest(t, plan, same)

	signers[0] = 99
	message[0] ^= 0xff
	gotSigners := plan.Signers()
	gotSigners[0] = 99
	gotMessage := plan.Message()
	gotMessage[0] ^= 0xff
	if !bytes.Equal(partyIDsBytes(plan.Signers()), partyIDsBytes([]tss.PartyID{1, 2})) {
		t.Fatal("sign plan signer getter or constructor aliases caller memory")
	}
	if !bytes.Equal(plan.Message(), []byte("plan-bound message")) {
		t.Fatal("sign plan message getter or constructor aliases caller memory")
	}

	otherMessage, err := NewSignPlan(SignPlanOption{
		Key: shares[1], SessionID: sessionID, Signers: []tss.PartyID{1, 2}, Context: testFROSTSigningContext(), Message: []byte("other message"), Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDifferentPlanDigest(t, "message", plan, otherMessage)

	otherShares := frostKeygen(t, 2, 4)
	otherKey, err := NewSignPlan(SignPlanOption{
		Key: otherShares[1], SessionID: sessionID, Signers: []tss.PartyID{1, 2}, Context: testFROSTSigningContext(), Message: []byte("plan-bound message"), Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDifferentPlanDigest(t, "key metadata", plan, otherKey)
}

func TestFROSTKeygenMixedPlanHashRejectsWithoutStateMutation(t *testing.T) {
	t.Parallel()

	sessionID := frostPlanTestSession(0x31)
	parties := []tss.PartyID{1, 2, 3}
	guard1 := testFROSTGuard(1, parties, sessionID)
	guard2 := testFROSTGuard(2, parties, sessionID)
	plan1 := mustFROSTKeygenPlan(t, sessionID, parties, 2)
	plan2 := mustFROSTKeygenPlan(t, sessionID, parties, 3)

	s1, _, err := StartKeygen(plan1, tss.LocalConfig{Self: 1}, guard1)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(plan2, tss.LocalConfig{Self: 2}, guard2)
	if err != nil {
		t.Fatal(err)
	}

	env, ok := findEnvelopeTo(out2, 1, payloadKeygenShare)
	if !ok {
		t.Fatal("missing keygen share from party 2 to party 1")
	}
	beforeShares := len(s1.shares)
	beforeCommits := len(s1.commits)
	out, err := s1.HandleKeygenMessage(testutil.DeliverEnvelope(env))
	if len(out) != 0 {
		t.Fatalf("plan mismatch emitted %d envelopes", len(out))
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if len(s1.shares) != beforeShares || len(s1.commits) != beforeCommits {
		t.Fatal("plan mismatch mutated keygen state")
	}
	if s1.aborted {
		t.Fatal("plan mismatch aborted keygen session")
	}
}

func TestFROSTEarlyConfirmationPlanMismatchDoesNotMutate(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 2)
	confirmation, err := shares[2].KeygenConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	confirmation.PlanHash[0] ^= 1
	payload, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	s := &KeygenSession{
		cfg:            tss.ThresholdConfig{SessionID: confirmation.SessionID},
		planHash:       shares[1].PlanHashBytes(),
		confirmations:  make(map[tss.PartyID][]byte),
		chainCodes:     make(map[tss.PartyID][]byte),
		chainCodeComms: make(map[tss.PartyID][]byte),
	}
	_, err = s.handleKeygenConfirmation(tss.Envelope{
		Round:   keygenConfirmationRound,
		From:    confirmation.Sender,
		Payload: payload,
	})
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if !errors.Is(protocolErr.Err, errPlanHashMismatch) {
		t.Fatalf("confirmation error = %v, want plan mismatch sentinel", protocolErr.Err)
	}
	if len(s.confirmations) != 0 || len(s.chainCodes) != 0 {
		t.Fatal("early confirmation plan mismatch mutated keygen state")
	}
	if shouldAbortSession(err) {
		t.Fatal("early confirmation plan mismatch would abort keygen session")
	}
}

type digestPlan interface {
	Digest() ([]byte, error)
}

func assertSamePlanDigest(t *testing.T, a, b digestPlan) {
	t.Helper()
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(da, db) {
		t.Fatal("plan digests differ")
	}
}

func assertDifferentPlanDigest(t *testing.T, name string, a, b digestPlan) {
	t.Helper()
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(da, db) {
		t.Fatalf("plan digest did not bind %s", name)
	}
}

func mustFROSTKeygenPlan(t *testing.T, sessionID tss.SessionID, parties []tss.PartyID, threshold int) *KeygenPlan {
	t.Helper()
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID,
		Parties:   parties,
		Threshold: threshold,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func frostPlanTestSession(fill byte) tss.SessionID {
	var sessionID tss.SessionID
	for i := range sessionID {
		sessionID[i] = fill
	}
	return sessionID
}

func findEnvelopeTo(envelopes []tss.Envelope, to tss.PartyID, payloadType tss.PayloadType) (tss.Envelope, bool) {
	for _, env := range envelopes {
		if env.To == to && env.PayloadType == payloadType {
			return env, true
		}
	}
	return tss.Envelope{}, false
}

func partyIDsBytes(parties []tss.PartyID) []byte {
	out := make([]byte, 0, len(parties)*4)
	for _, id := range parties {
		out = append(out, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	return out
}
