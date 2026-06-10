package tss

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func testSessionID(t *testing.T) SessionID {
	t.Helper()
	id, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testPolicySet() PolicySet {
	ps, err := NewPolicySet(
		DeliveryPolicy{
			Protocol:             "test-proto",
			Round:                1,
			PayloadType:          "test.direct.plain",
			Mode:                 DeliveryDirect,
			Confidentiality:      ConfidentialityForbidden,
			BroadcastConsistency: BroadcastConsistencyNone,
		},
		DeliveryPolicy{
			Protocol:             "test-proto",
			Round:                1,
			PayloadType:          "test.direct.confidential",
			Mode:                 DeliveryDirect,
			Confidentiality:      ConfidentialityRequired,
			BroadcastConsistency: BroadcastConsistencyNone,
		},
		DeliveryPolicy{
			Protocol:             "test-proto",
			Round:                1,
			PayloadType:          "test.broadcast.plain",
			Mode:                 DeliveryBroadcast,
			Confidentiality:      ConfidentialityForbidden,
			BroadcastConsistency: BroadcastConsistencyNone,
		},
		DeliveryPolicy{
			Protocol:             "test-proto",
			Round:                1,
			PayloadType:          "test.broadcast.cert",
			Mode:                 DeliveryBroadcast,
			Confidentiality:      ConfidentialityForbidden,
			BroadcastConsistency: BroadcastConsistencyRequired,
		},
	)
	if err != nil {
		panic(err)
	}
	return ps
}

type guardTestEnv struct {
	guard     *EnvelopeGuard
	sessionID SessionID
}

func newGuardTestEnv(t *testing.T) guardTestEnv {
	t.Helper()
	sid := testSessionID(t)
	guard := NewTestEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, testPolicySet())
	return guardTestEnv{guard: guard, sessionID: sid}
}

func (e guardTestEnv) envelope(t *testing.T, payloadType PayloadType, to PartyID) Envelope {
	t.Helper()
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test-proto",
		Version:     Version,
		SessionID:   e.sessionID,
		Round:       1,
		From:        2,
		To:          to,
		PayloadType: payloadType,
		Payload:     []byte("test-payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate transport setting security context.
	env.Security = SecurityContext{
		Authenticated:      true,
		Confidential:       false,
		AuthenticatedParty: 2,
		ReceivedAtUnix:     1000,
	}
	return env
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func TestNewEnvelopeGuardRejectsNilReplayCache(t *testing.T) {
	_, err := NewEnvelopeGuard(1, PartySet{1, 2}, "test-proto", testSessionID(t), testPolicySet(), nil)
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("expected ErrMissingReplayCache, got %v", err)
	}
}

func TestNewEnvelopeGuardRejectsInvalidSessionID(t *testing.T) {
	_, err := NewEnvelopeGuard(1, PartySet{1, 2}, "test-proto", SessionID{}, testPolicySet(), NewInMemoryReplayCache())
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected ErrInvalidSessionID, got %v", err)
	}
}

func TestNewEnvelopeGuardRejectsSelfNotInParties(t *testing.T) {
	_, err := NewEnvelopeGuard(99, PartySet{1, 2}, "test-proto", testSessionID(t), testPolicySet(), NewInMemoryReplayCache())
	if err == nil {
		t.Fatal("expected error for self not in parties")
	}
}

func TestGuardRejectsWrongProtocol(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.Protocol = "wrong-proto"
	err := env.guard.Validate(e)
	if err == nil {
		t.Fatal("expected rejection for wrong protocol")
	}
}

func TestGuardRejectsWrongSession(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.SessionID = testSessionID(t) // different session
	err := env.guard.Validate(e)
	if err == nil {
		t.Fatal("expected rejection for wrong session")
	}
}

func TestGuardRejectsUnauthenticatedTransport(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.Security.Authenticated = false
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrUnauthenticatedTransport) {
		t.Fatalf("expected ErrUnauthenticatedTransport, got %v", err)
	}
}

func TestGuardRejectsSenderSpoofing(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.Security.AuthenticatedParty = 3 // transport says it's party 3, but env.From is 2
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrSenderIdentityMismatch) {
		t.Fatalf("expected ErrSenderIdentityMismatch, got %v", err)
	}
}

func TestGuardRejectsUnknownSender(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.From = 99 // not in party set
	e.Security.AuthenticatedParty = 99
	err := env.guard.Validate(e)
	if err == nil {
		t.Fatal("expected rejection for unknown sender")
	}
}

func TestGuardRejectsWrongRecipient(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 3) // directed to party 3, but self is 1
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrWrongRecipient) {
		t.Fatalf("expected ErrWrongRecipient, got %v", err)
	}
}

func TestGuardRejectsBroadcastAsDirect(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 0) // To==0 but policy says DeliveryDirect
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrExpectedDirectMessage) {
		t.Fatalf("expected ErrExpectedDirectMessage, got %v", err)
	}
}

func TestGuardRejectsDirectAsBroadcast(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.plain", 1) // To!=0 but policy says DeliveryBroadcast
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrExpectedBroadcastMessage) {
		t.Fatalf("expected ErrExpectedBroadcastMessage, got %v", err)
	}
}

func TestGuardRejectsPlaintextConfidentialMessage(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.confidential", 1)
	e.Security.Confidential = false // policy requires confidential
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrMissingConfidentiality) {
		t.Fatalf("expected ErrMissingConfidentiality, got %v", err)
	}
}

func TestGuardRejectsUnexpectedConfidentiality(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.Security.Confidential = true // policy forbids confidential
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrUnexpectedConfidentiality) {
		t.Fatalf("expected ErrUnexpectedConfidentiality, got %v", err)
	}
}

func TestGuardDropsDuplicate(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	if err := env.guard.Validate(e); err != nil {
		t.Fatalf("first validation should pass, got %v", err)
	}
	// Second delivery of the same message returns ErrDuplicateMessage so
	// callers can drop it immediately without further processing.
	if err := env.guard.Validate(e); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("duplicate should return ErrDuplicateMessage, got %v", err)
	}
}

func TestGuardRejectsTamperedTranscript(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	e.Payload = []byte("tampered-payload") // change payload but keep old hash
	err := env.guard.Validate(e)
	if err == nil {
		t.Fatal("expected transcript hash mismatch rejection")
	}
}

func TestGuardRejectsUnknownPayloadPolicy(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.unknown.type", 1)
	e = e.RecomputeTranscriptHash()
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrUnknownPayloadPolicy) {
		t.Fatalf("expected ErrUnknownPayloadPolicy, got %v", err)
	}
}

func TestGuardRejectsMissingBroadcastCertificate(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.cert", 0)
	e.Broadcast = nil // policy requires certificate
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrMissingBroadcastCertificate) {
		t.Fatalf("expected ErrMissingBroadcastCertificate, got %v", err)
	}
}

func TestGuardAcceptsValidDirectMessage(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	if err := env.guard.Validate(e); err != nil {
		t.Fatalf("valid direct message should pass, got %v", err)
	}
}

func TestGuardAcceptsValidBroadcastMessage(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.plain", 0)
	if err := env.guard.Validate(e); err != nil {
		t.Fatalf("valid broadcast message should pass, got %v", err)
	}
}

func TestGuardAcceptsValidConfidentialMessage(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.confidential", 1)
	e.Security.Confidential = true
	if err := env.guard.Validate(e); err != nil {
		t.Fatalf("valid confidential message should pass, got %v", err)
	}
}

func TestGuardAcceptsBroadcastWithValidCertificate(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.cert", 0)
	payloadHash := sha256Sum(e.Payload)
	cert := &BroadcastCertificate{
		Protocol:       "test-proto",
		SessionID:      e.SessionID,
		Round:          1,
		From:           2,
		PayloadType:    "test.broadcast.cert",
		PayloadHash:    payloadHash,
		TranscriptHash: e.TranscriptHash,
		Recipients:     PartySet{1, 2, 3},
		Acks: []BroadcastAck{
			{Party: 1, PayloadHash: payloadHash, TranscriptHash: e.TranscriptHash},
			{Party: 2, PayloadHash: payloadHash, TranscriptHash: e.TranscriptHash},
			{Party: 3, PayloadHash: payloadHash, TranscriptHash: e.TranscriptHash},
		},
	}
	e.Broadcast = cert
	if err := env.guard.Validate(e); err != nil {
		t.Fatalf("valid certificate should pass, got %v", err)
	}
}

func TestBroadcastRejectsIncompleteAckSet(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.cert", 0)
	payloadHash := sha256Sum(e.Payload)
	cert := &BroadcastCertificate{
		Protocol:       "test-proto",
		SessionID:      e.SessionID,
		Round:          1,
		From:           2,
		PayloadType:    "test.broadcast.cert",
		PayloadHash:    payloadHash,
		TranscriptHash: e.TranscriptHash,
		Recipients:     PartySet{1, 2, 3},
		Acks: []BroadcastAck{
			{Party: 1, PayloadHash: payloadHash, TranscriptHash: e.TranscriptHash},
			// Missing party 2 and 3
		},
	}
	e.Broadcast = cert
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrInvalidBroadcastCertificate) {
		t.Fatalf("expected ErrInvalidBroadcastCertificate, got %v", err)
	}
}

func TestBroadcastRejectsWrongDigestAck(t *testing.T) {
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.cert", 0)
	payloadHash := sha256Sum(e.Payload)
	wrongHash := sha256Sum([]byte("wrong"))
	cert := &BroadcastCertificate{
		Protocol:       "test-proto",
		SessionID:      e.SessionID,
		Round:          1,
		From:           2,
		PayloadType:    "test.broadcast.cert",
		PayloadHash:    payloadHash,
		TranscriptHash: e.TranscriptHash,
		Recipients:     PartySet{1, 2, 3},
		Acks: []BroadcastAck{
			{Party: 1, PayloadHash: payloadHash, TranscriptHash: e.TranscriptHash},
			{Party: 2, PayloadHash: wrongHash, TranscriptHash: e.TranscriptHash}, // wrong digest
			{Party: 3, PayloadHash: payloadHash, TranscriptHash: e.TranscriptHash},
		},
	}
	e.Broadcast = cert
	err := env.guard.Validate(e)
	if !errors.Is(err, ErrInvalidBroadcastCertificate) {
		t.Fatalf("expected ErrInvalidBroadcastCertificate, got %v", err)
	}
}

// --- ValidateEnvelopePolicy tests ---

func TestValidateEnvelopePolicyRejectsUnknownPayloadType(t *testing.T) {
	env := testEnvelope("test-proto", 1, "test.unknown.payload", 2, 0)
	err := ValidateEnvelopePolicy(env, 1, testPolicySet())
	if !errors.Is(err, ErrUnknownPayloadPolicy) {
		t.Fatalf("expected ErrUnknownPayloadPolicy, got %v", err)
	}
}

func TestValidateEnvelopePolicyRejectsDirectAsBroadcast(t *testing.T) {
	// Direct-only payload sent with To=0 (broadcast) should fail.
	env := testEnvelope("test-proto", 1, "test.direct.confidential", 2, 0)
	err := ValidateEnvelopePolicy(env, 1, testPolicySet())
	if !errors.Is(err, ErrExpectedDirectMessage) {
		t.Fatalf("expected ErrExpectedDirectMessage, got %v", err)
	}
}

func TestValidateEnvelopePolicyRejectsBroadcastAsDirect(t *testing.T) {
	// Broadcast-only payload sent with To!=0 should fail.
	env := testEnvelope("test-proto", 1, "test.broadcast.plain", 2, 1)
	err := ValidateEnvelopePolicy(env, 1, testPolicySet())
	if !errors.Is(err, ErrExpectedBroadcastMessage) {
		t.Fatalf("expected ErrExpectedBroadcastMessage, got %v", err)
	}
}

func TestValidateEnvelopePolicyRejectsWrongRecipient(t *testing.T) {
	// Direct message addressed to wrong party.
	env := testEnvelope("test-proto", 1, "test.direct.confidential", 2, 3)
	err := ValidateEnvelopePolicy(env, 1, testPolicySet())
	if !errors.Is(err, ErrWrongRecipient) {
		t.Fatalf("expected ErrWrongRecipient, got %v", err)
	}
}

func TestValidateEnvelopePolicyRejectsMissingConfidentiality(t *testing.T) {
	// Confidential-required payload with Confidential=false.
	env := testEnvelope("test-proto", 1, "test.direct.confidential", 2, 1)
	env.Security.Authenticated = true
	env.Security.Confidential = false
	err := ValidateEnvelopePolicy(env, 1, testPolicySet())
	if !errors.Is(err, ErrMissingConfidentiality) {
		t.Fatalf("expected ErrMissingConfidentiality, got %v", err)
	}
}

func TestValidateEnvelopePolicyRejectsUnexpectedConfidentiality(t *testing.T) {
	// Confidential-forbidden payload with Confidential=true.
	env := testEnvelope("test-proto", 1, "test.direct.plain", 2, 1)
	env.Security.Authenticated = true
	env.Security.Confidential = true
	err := ValidateEnvelopePolicy(env, 1, testPolicySet())
	if !errors.Is(err, ErrUnexpectedConfidentiality) {
		t.Fatalf("expected ErrUnexpectedConfidentiality, got %v", err)
	}
}

func TestValidateEnvelopePolicyAllowsDirectConfidential(t *testing.T) {
	// Correct direct+confidential should pass.
	env := testEnvelope("test-proto", 1, "test.direct.confidential", 2, 1)
	env.Security.Authenticated = true
	env.Security.Confidential = true
	if err := ValidateEnvelopePolicy(env, 1, testPolicySet()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateEnvelopePolicyAllowsBroadcast(t *testing.T) {
	env := testEnvelope("test-proto", 1, "test.broadcast.plain", 2, 0)
	if err := ValidateEnvelopePolicy(env, 1, testPolicySet()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// testEnvelope builds a minimal envelope for policy testing.
func testEnvelope(protocol ProtocolID, round uint8, payloadType PayloadType, from, to PartyID) Envelope {
	return Envelope{
		Protocol:    protocol,
		Version:     Version,
		SessionID:   SessionID{1},
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     []byte("test"),
	}
}
