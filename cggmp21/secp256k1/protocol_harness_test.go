package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// fixtureKey identifies a cached keygen fixture by its essential parameters.
type fixtureKey struct {
	threshold int
	n         int
}

type keygenFixtureEntry struct {
	once   sync.Once
	shares map[tss.PartyID]*KeyShare
	err    error
}

// keygenFixtureCache avoids repeated full-DKG executions for identical
// (threshold, n) tuples across integration tests. Each call returns
// independent clones, so callers may mutate their copy freely.
var keygenFixtureCache sync.Map // map[fixtureKey]*keygenFixtureEntry

// CachedKeygenShares returns independent clones of a cached keygen fixture.
//
// Key shares always include a 32-byte chain code. HD-specific tests should use
// the same cached shares and exercise derivation logic separately; HD is not a
// keygen fixture dimension unless production keygen later gains a true non-HD
// mode.
func CachedKeygenShares(t testing.TB, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	key := fixtureKey{threshold: threshold, n: n}
	actual, _ := keygenFixtureCache.LoadOrStore(key, &keygenFixtureEntry{})
	entry := actual.(*keygenFixtureEntry)
	entry.once.Do(func() {
		shares, fromFixture, err := loadOrGenerateKeygenFixture(threshold, n)
		if err != nil {
			entry.err = err
			return
		}
		if !fromFixture {
			t.Logf("no committed keygen fixture for %d-of-%d; running full DKG fallback", threshold, n)
		}
		entry.shares = cloneKeyShareMap(shares)
	})
	if entry.err != nil {
		keygenFixtureCache.Delete(key)
		t.Fatalf("cached keygen fixture %d-of-%d: %v", threshold, n, entry.err)
	}
	if entry.shares == nil {
		keygenFixtureCache.Delete(key)
		t.Fatalf("cached keygen fixture %d-of-%d was not initialized", threshold, n)
	}
	return cloneKeyShareMap(entry.shares)
}

// cachedKeygenFixture is a convenience wrapper around CachedKeygenShares for
// tests that use the package-local harness.
func cachedKeygenFixture(t testing.TB, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	return CachedKeygenShares(t, threshold, n)
}

func cloneKeyShareMap(shares map[tss.PartyID]*KeyShare) map[tss.PartyID]*KeyShare {
	out := make(map[tss.PartyID]*KeyShare, len(shares))
	for id, ks := range shares {
		out[id] = cloneKeyShareValue(ks)
	}
	return out
}

type protocolHarness struct {
	threshold int
	parties   tss.PartySet
	shares    map[tss.PartyID]*KeyShare
}

func newHarness(t testing.TB, threshold, n int) *protocolHarness {
	t.Helper()
	parties := make(tss.PartySet, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	return &protocolHarness{
		threshold: threshold,
		parties:   parties,
		shares:    cachedKeygenFixture(t, threshold, n),
	}
}

func (h *protocolHarness) evidenceContext(sessionID tss.SessionID, receiver tss.PartyID, signers tss.PartySet, presign *Presign) EvidenceContext {
	ctx := secpEvidenceContext(h.shares[receiver], signers, presign)
	ctx.SessionID = sessionID
	return ctx
}

func secpKeygenWithoutConfirmation(t testing.TB, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make(tss.PartySet, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(testutil.DeliverEnvelope(env)); err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		if sessions[id].pending == nil {
			t.Fatalf("keygen pending share not complete for %d", id)
		}
		out[id] = cloneKeyShareValue(sessions[id].pending)
	}
	return out
}

func secpKeygen(t testing.TB, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	shares, err := runSecpKeygen(threshold, n)
	if err != nil {
		t.Fatal(err)
	}
	return shares
}

func runSecpKeygen(threshold, n int) (map[tss.PartyID]*KeyShare, error) {
	session, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, err
	}
	parties := make(tss.PartySet, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			return nil, fmt.Errorf("start keygen party %d: %w", id, err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	if err := deliverKeygenMessagesE(sessions, parties, messages); err != nil {
		return nil, err
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	var pub []byte
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			return nil, fmt.Errorf("keygen not complete for party %d", id)
		}
		if pub == nil {
			pub = share.state.publicKey
		} else if !bytes.Equal(pub, share.state.publicKey) {
			return nil, fmt.Errorf("group public key mismatch for party %d", id)
		}
		if err := validateKeySharePartyDataSet(share, parties); err != nil {
			return nil, fmt.Errorf("keygen party %d: %w", id, err)
		}
		out[id] = share
	}
	return out, nil
}

func secpKeygenWithPlanOption(t testing.TB, threshold, n int, option KeygenPlanOption) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make(tss.PartySet, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := startCGGMP21KeygenWithPlanOption(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session}, option)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	deliverKeygenMessages(t, sessions, parties, messages)
	out := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		out[id] = share
	}
	return out
}

func secpPresign(t testing.TB, shares map[tss.PartyID]*KeyShare, signers tss.PartySet) map[tss.PartyID]*Presign {
	return secpPresignWithContext(t, shares, signers, testPresignContext())
}

func secpPresignWithContext(t testing.TB, shares map[tss.PartyID]*KeyShare, signers tss.PartySet, ctx PresignContext) map[tss.PartyID]*Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	presignSessions := map[tss.PartyID]*PresignSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := startCGGMP21PresignWithContext(shares[id], sessionID, signers, ctx)
		if err != nil {
			t.Fatal(err)
		}
		presignSessions[id] = session
		messages = append(messages, out...)
	}
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].HandlePresignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			messages = append(messages, out...)
		}
	}
	out := make(map[tss.PartyID]*Presign, len(signers))
	for _, id := range signers {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			t.Fatalf("presign not complete for %d", id)
		}
		out[id] = presign
	}
	return out
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

func secpEvidenceContext(share *KeyShare, signers tss.PartySet, presign *Presign) EvidenceContext {
	paillierPublicKeys, err := share.paillierPublicShares(testLimits())
	if err != nil {
		panic(err)
	}
	ctx := EvidenceContext{
		Parties:              share.state.parties.Clone(),
		PublicKey:            append([]byte(nil), share.state.publicKey...),
		PaillierPublicKeys:   paillierPublicKeys,
		Signers:              signers.Clone(),
		KeygenTranscriptHash: append([]byte(nil), share.state.keygenTranscriptHash...),
	}
	if presign != nil {
		ctx.PresignTranscriptHash = append([]byte(nil), presign.state.transcriptHash...)
	}
	return ctx
}

func assertBlameEvidence(t testing.TB, err error, ctx EvidenceContext) *tss.ProtocolError {
	t.Helper()
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if protocolErr.Blame == nil || len(protocolErr.Blame.Evidence) == 0 {
		t.Fatalf("missing blame evidence: %v", err)
	}
	if verifyErr := VerifyBlameEvidence(protocolErr.Blame.Evidence, ctx); verifyErr != nil {
		t.Fatalf("blame evidence did not verify: %v", verifyErr)
	}
	lower := strings.ToLower(string(protocolErr.Blame.Evidence))
	for _, forbidden := range []string{"secret", "nonce", "k_share", "chi_share", "paillier_private"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("evidence contains sensitive field marker %q: %s", forbidden, protocolErr.Blame.Evidence)
		}
	}
	decoded, err := tss.UnmarshalBlameEvidence(protocolErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Protocol = "wrong-protocol"
	mutated, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyBlameEvidence(mutated, ctx) == nil {
		t.Fatal("tampered blame evidence verified")
	}
	return protocolErr
}

func assertNoBlame(t testing.TB, protocolErr *tss.ProtocolError) {
	t.Helper()
	if protocolErr.Blame != nil {
		t.Fatalf("%s unexpectedly carried blame: %#v", protocolErr.Code, protocolErr.Blame)
	}
}

func runCGGMP21Reshare(t testing.TB, oldShares map[tss.PartyID]*KeyShare, newParties tss.PartySet, newThreshold int) (map[tss.PartyID]*KeyShare, map[tss.PartyID]*ReshareSession) {
	t.Helper()
	var reference *KeyShare
	for _, share := range oldShares {
		reference = share
		break
	}
	if reference == nil {
		t.Fatal("missing old shares")
		return nil, nil
	}
	return runCGGMP21ReshareWithDealers(t, oldShares, reference.state.parties, newParties, newThreshold)
}

func runCGGMP21ReshareWithDealers(t testing.TB, oldShares map[tss.PartyID]*KeyShare, dealerParties, newParties tss.PartySet, newThreshold int) (map[tss.PartyID]*KeyShare, map[tss.PartyID]*ReshareSession) {
	t.Helper()
	var reference *KeyShare
	for _, share := range oldShares {
		reference = share
		break
	}
	if reference == nil {
		t.Fatal("missing old shares")
	}
	newParties = tss.SortParties(newParties)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	dealerParties = tss.SortParties(dealerParties)
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey:         reference,
		SessionID:      sessionID,
		DealerParties:  dealerParties,
		NewParties:     newParties,
		NewThreshold:   newThreshold,
		Limits:         testLimitsPtr(),
		SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*ReshareSession)
	queue := make([]tss.Envelope, 0)
	for _, id := range dealerParties {
		var session *ReshareSession
		var out []tss.Envelope
		if tss.ContainsParty(newParties, id) {
			session, out, err = startCGGMP21ReshareOverlap(oldShares[id], plan, nil)
		} else {
			session, out, err = startCGGMP21ReshareDealer(oldShares[id], plan, nil)
		}
		if err != nil {
			t.Fatalf("start old dealer %d: %v", id, err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	for _, id := range newParties {
		if tss.ContainsParty(dealerParties, id) {
			continue
		}
		session, out, err := startCGGMP21ReshareReceiver(plan, id, nil)
		if err != nil {
			t.Fatalf("start new receiver %d: %v", id, err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	deliverCGGMP21ReshareMessages(t, queue, sessions)
	newShares := make(map[tss.PartyID]*KeyShare, len(newParties))
	for _, id := range newParties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("reshare did not complete for new party %d", id)
		}
		newShares[id] = share
	}
	validateCGGMP21Shares(t, newShares, newParties)
	return newShares, sessions
}

func deliverCGGMP21ReshareMessages(t testing.TB, queue []tss.Envelope, sessions map[tss.PartyID]*ReshareSession) {
	t.Helper()
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for id, session := range sessions {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := session.HandleReshareMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
}

func validateCGGMP21Shares(t testing.TB, shares map[tss.PartyID]*KeyShare, parties tss.PartySet) {
	t.Helper()
	for _, id := range parties {
		if err := validateKeySharePartyDataSet(shares[id], parties); err != nil {
			t.Fatalf("validate new share %d party data: %v", id, err)
		}
		if err := shares[id].ValidateWithLimits(testLimits()); err != nil {
			t.Fatalf("validate new share %d: %v", id, err)
		}
	}
}

func validateKeySharePartyDataSet(share *KeyShare, parties tss.PartySet) error {
	if share == nil || share.state == nil {
		return errors.New("nil key share")
	}
	if len(share.state.partyData) != len(parties) {
		return fmt.Errorf("party data count %d != party count %d", len(share.state.partyData), len(parties))
	}
	for _, id := range parties {
		if _, ok := share.state.partyData[id]; !ok {
			return fmt.Errorf("missing party data for %d", id)
		}
	}
	for id := range share.state.partyData {
		if !tss.ContainsParty(parties, id) {
			return fmt.Errorf("unexpected party data for %d", id)
		}
	}
	return nil
}
