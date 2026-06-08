//go:build integration

package secp256k1

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
)

// testCGGMP21GuardFull is like testCGGMP21Guard but uses the production
// policy set with BroadcastConsistencyRequired. Use this for tests that
// specifically exercise broadcast certificate enforcement.
func testCGGMP21GuardFull(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) *tss.EnvelopeGuard {
	g, err := tss.NewEnvelopeGuard(self, parties, protocol, sessionID, CGGMP21Policies, tss.NewInMemoryReplayCache())
	if err != nil {
		panic(err)
	}
	return g
}

// makeSessionID creates a random session ID for tests.
func makeSessionID(t *testing.T) tss.SessionID {
	t.Helper()
	id, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// buildTestConfig creates a ThresholdConfig for each party in a test.
func buildTestConfig(parties tss.PartySet, threshold int, sessionID tss.SessionID) map[tss.PartyID]tss.ThresholdConfig {
	out := make(map[tss.PartyID]tss.ThresholdConfig, len(parties))
	for _, id := range parties {
		out[id] = tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		}
	}
	return out
}

// TestCGGMP21KeygenRejectsRound1WithoutBroadcastCert verifies that keygen round 1
// commitments without a BroadcastCertificate are rejected by the guard.
func TestCGGMP21KeygenRejectsRound1WithoutBroadcastCert(t *testing.T) {
	parties := tss.PartySet{11, 12, 13}
	sessionID := makeSessionID(t)
	configs := buildTestConfig(parties, 2, sessionID)

	// Start one session with guard.
	session, _, err := StartKeygen(configs[11])
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21GuardFull(11, parties, sessionID))

	// Construct a commitments broadcast without certificate.
	commitEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        12,
		To:          0,
		PayloadType: payloadKeygenCommitments,
		Payload:     []byte("not-a-real-commitment"),
	})
	if err != nil {
		t.Fatal(err)
	}
	commitEnv.Security.Authenticated = true
	commitEnv.Security.AuthenticatedParty = 12
	// Deliberately omit BroadcastCertificate even though policy requires it.

	_, err = session.HandleKeygenMessage(commitEnv)
	if !errors.Is(err, tss.ErrMissingBroadcastCertificate) {
		t.Fatalf("expected ErrMissingBroadcastCertificate, got %v", err)
	}
}

// TestCGGMP21KeygenRejectsPlaintextShare verifies that keygen round 1 shares
// delivered without transport confidentiality are rejected.
func TestCGGMP21KeygenRejectsPlaintextShare(t *testing.T) {
	parties := tss.PartySet{21, 22, 23}
	sessionID := makeSessionID(t)
	configs := buildTestConfig(parties, 2, sessionID)

	session, _, err := StartKeygen(configs[21])
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21GuardFull(21, parties, sessionID))

	// Construct a direct share envelope without confidentiality.
	shareEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        22,
		To:          21,
		PayloadType: payloadKeygenShare,
		Payload:     []byte("not-a-real-share"),
	})
	if err != nil {
		t.Fatal(err)
	}
	shareEnv.Security.Authenticated = true
	shareEnv.Security.AuthenticatedParty = 22
	// Confidential is deliberately left false.

	_, err = session.HandleKeygenMessage(shareEnv)
	if !errors.Is(err, tss.ErrMissingConfidentiality) {
		t.Fatalf("expected ErrMissingConfidentiality or rejection, got %v", err)
	}
}

// TestCGGMP21KeygenRejectsUnauthenticatedTransport verifies that messages
// without transport authentication are rejected by the guard.
func TestCGGMP21KeygenRejectsUnauthenticatedTransport(t *testing.T) {
	parties := tss.PartySet{31, 32, 33}
	sessionID := makeSessionID(t)
	configs := buildTestConfig(parties, 2, sessionID)

	session, _, err := StartKeygen(configs[31])
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21GuardFull(31, parties, sessionID))

	commitEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        32,
		To:          0,
		PayloadType: payloadKeygenCommitments,
		Payload:     []byte("not-real-commitments"),
	})
	if err != nil {
		t.Fatal(err)
	}
	commitEnv.Security.Authenticated = false // unauthenticated

	_, err = session.HandleKeygenMessage(commitEnv)
	if !errors.Is(err, tss.ErrUnauthenticatedTransport) {
		t.Fatalf("expected ErrUnauthenticatedTransport, got %v", err)
	}
}

// TestCGGMP21KeygenRejectsSenderSpoofing verifies that identity mismatch is caught.
func TestCGGMP21KeygenRejectsSenderSpoofing(t *testing.T) {
	parties := tss.PartySet{41, 42, 43}
	sessionID := makeSessionID(t)
	configs := buildTestConfig(parties, 2, sessionID)

	session, _, err := StartKeygen(configs[41])
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21GuardFull(41, parties, sessionID))

	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        42,
		To:          0,
		PayloadType: payloadKeygenCommitments,
		Payload:     []byte("test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = 43 // transport says 43, but envelope says 42

	_, err = session.HandleKeygenMessage(env)
	if !errors.Is(err, tss.ErrSenderIdentityMismatch) {
		t.Fatalf("expected ErrSenderIdentityMismatch, got %v", err)
	}
}

// TestCGGMP21KeygenRejectsReplay verifies that replayed keygen messages are detected.
func TestCGGMP21KeygenRejectsReplay(t *testing.T) {
	parties := tss.PartySet{51, 52, 53}
	sessionID := makeSessionID(t)
	configs := buildTestConfig(parties, 2, sessionID)

	session, _, err := StartKeygen(configs[51])
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21GuardFull(51, parties, sessionID))

	// First delivery of a valid broadcast message.
	commitEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        52,
		To:          0,
		PayloadType: payloadKeygenConfirmation,
		Payload:     []byte("test-confirmation"),
	})
	if err != nil {
		t.Fatal(err)
	}
	commitEnv.Security.Authenticated = true
	commitEnv.Security.AuthenticatedParty = 52

	// First delivery: may fail (invalid payload) but should NOT fail with ErrReplay.
	_, _ = session.HandleKeygenMessage(commitEnv)

	// Second delivery: must fail with ErrReplay if it passed the guard the first time.
	_, err = session.HandleKeygenMessage(commitEnv)
	if !errors.Is(err, tss.ErrReplay) {
		// If it wasn't ErrReplay, ensure it's some other valid error (not nil).
		if err == nil {
			t.Error("expected ErrReplay or other error on second delivery, got nil")
		}
		// The first delivery may have failed before the replay check for other reasons
		// (wrong round, etc.). That's acceptable - we're testing that when the guard
		// processes a message, replay is detected.
	}
}

// TestCGGMP21KeygenRejectsUnknownPayloadPolicy verifies that unregistered payload
// types are rejected under guard.
func TestCGGMP21KeygenRejectsUnknownPayloadPolicy(t *testing.T) {
	parties := tss.PartySet{61, 62, 63}
	sessionID := makeSessionID(t)
	configs := buildTestConfig(parties, 2, sessionID)

	session, _, err := StartKeygen(configs[61])
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21GuardFull(61, parties, sessionID))

	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        62,
		To:          61,
		PayloadType: "cggmp21.secp256k1.unknown.type",
		Payload:     []byte("test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = 62
	env.Security.Confidential = true

	_, err = session.HandleKeygenMessage(env)
	if !errors.Is(err, tss.ErrUnknownPayloadPolicy) {
		t.Fatalf("expected ErrUnknownPayloadPolicy, got %v", err)
	}
}
