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
	parties := tss.NewPartySet(3, 1, 2)
	plan, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSamePlanDigest(t, plan, same)

	parties[0] = 99
	snapshot, ok := plan.Snapshot()
	if !ok {
		t.Fatal("missing keygen plan snapshot")
	}
	snapshot.Parties[0] = 99
	again, ok := plan.Snapshot()
	if !ok || !bytes.Equal(partyIDsBytes(again.Parties), partyIDsBytes(tss.NewPartySet(1, 2, 3))) {
		t.Fatal("keygen plan snapshot or constructor aliases caller memory")
	}
	localLimits := DefaultLimits()
	localLimits.Payload.MaxMessageBytes--
	withLocalLimits, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2, 3), Threshold: 2, Limits: &localLimits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSamePlanDigest(t, plan, withLocalLimits)

	for name, other := range map[string]*KeygenPlan{
		"threshold": mustFROSTKeygenPlan(t, sessionID, tss.NewPartySet(1, 2, 3), 3),
		"session":   mustFROSTKeygenPlan(t, frostPlanTestSession(0x12), tss.NewPartySet(1, 2, 3), 2),
	} {
		assertDifferentPlanDigest(t, name, plan, other)
	}
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2), Threshold: 3,
	}); err == nil {
		t.Fatal("keygen plan accepted threshold greater than party count")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
	strictLimits := DefaultLimits()
	strictLimits.Threshold.MaxParties = 2
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2, 3), Threshold: 2, Limits: &strictLimits,
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

func TestFROSTRefreshAndResharePlanSnapshotsReturnOwnedCopies(t *testing.T) {
	shares := frostKeygen(t, 2, 3)

	refresh, err := NewRefreshPlan(RefreshPlanOption{
		OldKey: shares[1], SessionID: frostPlanTestSession(0x19),
	})
	if err != nil {
		t.Fatal(err)
	}
	refreshSnapshot, ok := refresh.Snapshot()
	if !ok {
		t.Fatal("missing refresh plan snapshot")
	}
	refreshSnapshot.Parties[0] = 99
	refreshSnapshot.PublicKey[0] ^= 0xff
	refreshSnapshot.ChainCode[0] ^= 0xff
	refreshSnapshot.OldKeygenTranscriptHash[0] ^= 0xff
	refreshSnapshot.OldPlanHash[0] ^= 0xff
	refreshSnapshot.OldCommitmentsHash[0] ^= 0xff
	refreshAgain, ok := refresh.Snapshot()
	if !ok || refreshAgain.Parties[0] != 1 ||
		bytes.Equal(refreshAgain.PublicKey, refreshSnapshot.PublicKey) ||
		bytes.Equal(refreshAgain.ChainCode, refreshSnapshot.ChainCode) ||
		bytes.Equal(refreshAgain.OldKeygenTranscriptHash, refreshSnapshot.OldKeygenTranscriptHash) ||
		bytes.Equal(refreshAgain.OldPlanHash, refreshSnapshot.OldPlanHash) ||
		bytes.Equal(refreshAgain.OldCommitmentsHash, refreshSnapshot.OldCommitmentsHash) {
		t.Fatal("refresh plan snapshot aliases internal state")
	}

	reshare, err := NewResharePlan(ResharePlanOption{
		OldKey: shares[1], SessionID: frostPlanTestSession(0x1a),
		NewParties: tss.NewPartySet(2, 3, 4), NewThreshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reshare.IsDealer(1) || reshare.IsReceiver(1) || reshare.IsOverlap(1) {
		t.Fatal("old-only party has inconsistent reshare roles")
	}
	if !reshare.IsDealer(2) || !reshare.IsReceiver(2) || !reshare.IsOverlap(2) {
		t.Fatal("overlap party has inconsistent reshare roles")
	}
	if reshare.IsDealer(4) || !reshare.IsReceiver(4) || reshare.IsOverlap(4) {
		t.Fatal("new-only party has inconsistent reshare roles")
	}
	reshareSnapshot, ok := reshare.Snapshot()
	if !ok {
		t.Fatal("missing reshare plan snapshot")
	}
	reshareSnapshot.OldParties[0] = 99
	reshareSnapshot.NewParties[0] = 99
	reshareSnapshot.OldPublicKey[0] ^= 0xff
	reshareSnapshot.OldChainCode[0] ^= 0xff
	reshareSnapshot.OldKeygenTranscriptHash[0] ^= 0xff
	reshareSnapshot.OldPlanHash[0] ^= 0xff
	reshareSnapshot.OldCommitmentsHash[0] ^= 0xff
	reshareAgain, ok := reshare.Snapshot()
	if !ok || reshareAgain.OldParties[0] != 1 || reshareAgain.NewParties[0] != 2 ||
		bytes.Equal(reshareAgain.OldPublicKey, reshareSnapshot.OldPublicKey) ||
		bytes.Equal(reshareAgain.OldChainCode, reshareSnapshot.OldChainCode) ||
		bytes.Equal(reshareAgain.OldKeygenTranscriptHash, reshareSnapshot.OldKeygenTranscriptHash) ||
		bytes.Equal(reshareAgain.OldPlanHash, reshareSnapshot.OldPlanHash) ||
		bytes.Equal(reshareAgain.OldCommitmentsHash, reshareSnapshot.OldCommitmentsHash) {
		t.Fatal("reshare plan snapshot aliases internal state")
	}
}

func TestFROSTSignPlanDigestBindsKeyMetadataAndCopies(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID := frostPlanTestSession(0x21)
	signers := tss.NewPartySet(2, 1)
	message := []byte("plan-bound message")

	limits := testLimits()
	plan, err := NewSignPlan(SignPlanOption{
		Key: shares[1],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   signers,
			Context:   testFROSTSigningContext(),
			Message:   message,
		},
		Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewSignPlan(SignPlanOption{
		Key: shares[2],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   tss.NewPartySet(1, 2),
			Context:   testFROSTSigningContext(),
			Message:   message,
		},
		Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSamePlanDigest(t, plan, same)

	signers[0] = 99
	message[0] ^= 0xff
	snapshot, ok := plan.Snapshot()
	if !ok {
		t.Fatal("missing sign plan snapshot")
	}
	snapshot.Intent.Signers[0] = 99
	snapshot.Intent.Message[0] ^= 0xff
	again, ok := plan.Snapshot()
	if !ok || !bytes.Equal(partyIDsBytes(again.Intent.Signers), partyIDsBytes(tss.NewPartySet(1, 2))) {
		t.Fatal("sign plan signer snapshot or constructor aliases caller memory")
	}
	if !bytes.Equal(again.Intent.Message, []byte("plan-bound message")) {
		t.Fatal("sign plan message snapshot or constructor aliases caller memory")
	}

	otherMessage, err := NewSignPlan(SignPlanOption{
		Key: shares[1],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   tss.NewPartySet(1, 2),
			Context:   testFROSTSigningContext(),
			Message:   []byte("other message"),
		},
		Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDifferentPlanDigest(t, "message", plan, otherMessage)

	otherShares := frostKeygen(t, 2, 4)
	otherKey, err := NewSignPlan(SignPlanOption{
		Key: otherShares[1],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   tss.NewPartySet(1, 2),
			Context:   testFROSTSigningContext(),
			Message:   []byte("plan-bound message"),
		},
		Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDifferentPlanDigest(t, "key metadata", plan, otherKey)
}

func TestFROSTSignPlanSignerCountPolicy(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID := frostPlanTestSession(0x22)
	message := []byte("default signer-count policy")
	context := testFROSTSigningContext()

	defaultPlan, err := NewSignPlan(SignPlanOption{
		Key: shares[1],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   tss.NewPartySet(3, 1, 2),
			Context:   context,
			Message:   message,
		},
	})
	if err != nil {
		t.Fatalf("default limits rejected threshold-or-more signer set: %v", err)
	}
	defaultSnapshot, ok := defaultPlan.Snapshot()
	if !ok {
		t.Fatal("missing default sign plan snapshot")
	}
	if !bytes.Equal(partyIDsBytes(defaultSnapshot.Intent.Signers), partyIDsBytes(tss.NewPartySet(1, 2, 3))) {
		t.Fatalf("default signers = %v, want [1 2 3]", defaultSnapshot.Intent.Signers)
	}

	strictLimits := DefaultLimits()
	strictLimits.Threshold.AllowOversizedSignerSet = false
	strictPlan, err := NewSignPlan(SignPlanOption{
		Key: shares[1],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   tss.NewPartySet(1, 2, 3),
			Context:   context,
			Message:   message,
		},
		Limits: &strictLimits,
	})
	if err == nil {
		t.Fatal("explicit exact-threshold policy accepted an oversized signer set")
	}
	if strictPlan != nil {
		t.Fatal("rejected exact-threshold policy returned a sign plan")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)

	exactPlan, err := NewSignPlan(SignPlanOption{
		Key: shares[1],
		Intent: tss.SignIntent{
			SessionID: sessionID,
			Signers:   tss.NewPartySet(1, 2),
			Context:   context,
			Message:   message,
		},
		Limits: &strictLimits,
	})
	if err != nil {
		t.Fatalf("explicit exact-threshold policy rejected threshold signers: %v", err)
	}
	assertDifferentPlanDigest(t, "signer set", defaultPlan, exactPlan)
}

func TestFROSTKeygenMixedPlanHashRejectsWithoutStateMutation(t *testing.T) {
	t.Parallel()

	sessionID := frostPlanTestSession(0x31)
	parties := tss.NewPartySet(1, 2, 3)
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

	env, ok := findEnvelopeTo(out2, tss.BroadcastPartyId, payloadKeygenCommitments)
	if !ok {
		t.Fatal("missing keygen commitment from party 2")
	}
	beforeShares := countNonNilShares(s1.round1)
	beforeCommits := countNonNilCommits(s1.round1)
	out, err := s1.Handle(testutil.DeliverEnvelope(env))
	if len(out) != 0 {
		t.Fatalf("plan mismatch emitted %d envelopes", len(out))
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if countNonNilShares(s1.round1) != beforeShares || countNonNilCommits(s1.round1) != beforeCommits {
		t.Fatal("plan mismatch mutated keygen state")
	}
	if s1.aborted {
		t.Fatal("plan mismatch aborted keygen session")
	}
}

func TestFROSTEarlyConfirmationPlanMismatchDoesNotMutate(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 2)
	confirmation, err := shares[2].NewConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	confirmation.PlanHash[0] ^= 1
	payload, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	s := &KeygenSession{
		cfg:           tss.ThresholdConfig{SessionID: confirmation.SessionID},
		limits:        testLimits(),
		planHash:      mustKeyShareMetadata(t, shares[1]).PlanHash,
		round1:        newFROSTKeygenRound1Inbox(tss.NewPartySet(confirmation.Sender)),
		confirmations: newFROSTKeygenConfirmationInbox(tss.NewPartySet(confirmation.Sender)),
	}
	_, err = s.buildAcceptKeygenConfirmationTx(tss.Envelope{
		Round:   keygenConfirmationRound,
		From:    confirmation.Sender,
		Payload: payload,
	})
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if !errors.Is(protocolErr.Err, tss.ErrPlanHashMismatch) {
		t.Fatalf("confirmation error = %v, want plan mismatch sentinel", protocolErr.Err)
	}
	if countNonNilConfirmations(s.confirmations) != 0 || countNonNilChainCodes(s.confirmations) != 0 {
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

func mustFROSTKeygenPlan(t *testing.T, sessionID tss.SessionID, parties tss.PartySet, threshold int) *KeygenPlan {
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

func partyIDsBytes(parties tss.PartySet) []byte {
	out := make([]byte, 0, len(parties)*4)
	for _, id := range parties {
		out = append(out, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	return out
}

func countNonNilShares(in *frostKeygenRound1Inbox) int {
	n := 0
	for _, d := range in.slots {
		if d.share != nil {
			n++
		}
	}
	return n
}

func countNonNilCommits(in *frostKeygenRound1Inbox) int {
	n := 0
	for _, d := range in.slots {
		if d.commitments != nil {
			n++
		}
	}
	return n
}

func countNonNilConfirmations(in *frostKeygenConfirmationInbox) int {
	n := 0
	for _, confirmation := range in.confirmations {
		if confirmation != nil {
			n++
		}
	}
	return n
}

func countNonNilChainCodes(in *frostKeygenConfirmationInbox) int {
	n := 0
	for _, chainCode := range in.chainCodes {
		if chainCode != nil {
			n++
		}
	}
	return n
}
