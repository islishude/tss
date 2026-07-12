package tss

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
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
			PayloadType:          "test.direct.optional",
			Mode:                 DeliveryDirect,
			Confidentiality:      ConfidentialityOptional,
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
		DeliveryPolicy{
			Protocol:             "test-proto",
			Round:                1,
			PayloadType:          "test.broadcast.optional",
			Mode:                 DeliveryBroadcast,
			Confidentiality:      ConfidentialityOptional,
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
	return env
}

func (e guardTestEnv) inbound(env Envelope, info ReceiveInfo, cert *BroadcastCertificate) InboundEnvelope {
	if info.Peer == 0 && info.Protection == ChannelProtectionUnknown {
		info = ReceiveInfo{
			Peer:       env.From,
			Protection: ChannelPlaintext,
			ChannelID:  "test",
			PeerKeyID:  "party-2",
			ReceivedAt: time.Unix(1, 0),
		}
	}
	return InboundEnvelope{
		env:         env.Clone(),
		receiveInfo: info,
		broadcast:   cert.Clone(),
	}
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func guardReplayCacheEntries(t *testing.T, guard *EnvelopeGuard) int {
	t.Helper()
	cache, ok := guard.ReplayCache.(*InMemoryReplayCache)
	if !ok {
		t.Fatalf("unexpected replay cache type %T", guard.ReplayCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.seen)
}

func TestEnvelopeGuardValidateWithoutReplayAllowsExactRetry(t *testing.T) {
	t.Parallel()
	testEnv := newGuardTestEnv(t)
	env := testEnv.envelope(t, "test.direct.plain", 1)
	in := testEnv.inbound(env, ReceiveInfo{}, nil)

	if err := testEnv.guard.ValidateWithoutReplay(in, PartySet{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if got := guardReplayCacheEntries(t, testEnv.guard); got != 0 {
		t.Fatalf("stateless validation stored %d replay entries", got)
	}
	if err := testEnv.guard.Validate(in); err != nil {
		t.Fatalf("exact retry after stateless validation: %v", err)
	}
	if got := guardReplayCacheEntries(t, testEnv.guard); got != 1 {
		t.Fatalf("accepted retry stored %d replay entries, want 1", got)
	}
	if err := testEnv.guard.Validate(in); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("accepted duplicate = %v, want %v", err, ErrDuplicateMessage)
	}
	conflict := env.Clone()
	conflict.Payload = []byte("conflicting-payload")
	if err := testEnv.guard.Validate(testEnv.inbound(conflict, ReceiveInfo{}, nil)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("accepted conflict = %v, want %v", err, ErrEquivocation)
	}
}

func TestNewEnvelopeGuardRejectsNilReplayCache(t *testing.T) {
	t.Parallel()
	_, err := NewEnvelopeGuard(1, PartySet{1, 2}, "test-proto", testSessionID(t), testPolicySet(), nil)
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("expected ErrMissingReplayCache, got %v", err)
	}
}

func TestNewEnvelopeGuardRejectsInvalidSessionID(t *testing.T) {
	t.Parallel()
	_, err := NewEnvelopeGuard(1, PartySet{1, 2}, "test-proto", SessionID{}, testPolicySet(), NewInMemoryReplayCache())
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected ErrInvalidSessionID, got %v", err)
	}
}

func TestNewEnvelopeGuardRejectsSelfNotInParties(t *testing.T) {
	t.Parallel()
	_, err := NewEnvelopeGuard(99, PartySet{1, 2}, "test-proto", testSessionID(t), testPolicySet(), NewInMemoryReplayCache())
	if err == nil {
		t.Fatal("expected error for self not in parties")
	}
}

func TestNewEnvelopeGuardRejectsEmptyParties(t *testing.T) {
	t.Parallel()
	_, err := NewEnvelopeGuard(1, NewPartySet(), "test-proto", testSessionID(t), testPolicySet(), NewInMemoryReplayCache())
	if err == nil {
		t.Fatal("expected error for empty parties")
	}
}

func TestEnvelopeGuardRejectsSelfSenderBeforeReplayState(t *testing.T) {
	t.Parallel()
	session := testSessionID(t)
	guard := NewTestEnvelopeGuard(1, PartySet{1, 2}, "test-proto", session, testPolicySet())
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test-proto",
		SessionID:   session,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "direct",
		Payload:     []byte("reflected"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	in, err := OpenEnvelope(raw, ReceiveInfo{Peer: 1, Protection: ChannelConfidential})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Validate(in); !errors.Is(err, ErrSelfSender) {
		t.Fatalf("Validate got %v, want ErrSelfSender", err)
	}
	if got := guardReplayCacheEntries(t, guard); got != 0 {
		t.Fatalf("self-sender envelope stored %d replay entries", got)
	}
}

func TestGuardValidateRejectsInvalidEnvelopeWithoutReplaySideEffect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		payloadType PayloadType
		to          PartyID
		mutate      func(t *testing.T, env guardTestEnv, e *Envelope)
		info        func(Envelope) ReceiveInfo
		wantErr     error
	}{
		{
			name:        "wrong protocol",
			payloadType: "test.direct.plain",
			to:          1,
			mutate: func(t *testing.T, _ guardTestEnv, e *Envelope) {
				t.Helper()
				e.Protocol = "wrong-proto"
			},
		},
		{
			name:        "wrong session",
			payloadType: "test.direct.plain",
			to:          1,
			mutate: func(t *testing.T, _ guardTestEnv, e *Envelope) {
				t.Helper()
				e.SessionID = testSessionID(t)
			},
		},
		{
			name:        "unknown sender",
			payloadType: "test.direct.plain",
			to:          1,
			mutate: func(t *testing.T, _ guardTestEnv, e *Envelope) {
				t.Helper()
				e.From = 99
			},
		},
		{
			name:        "unauthenticated transport",
			payloadType: "test.direct.plain",
			to:          1,
			info: func(env Envelope) ReceiveInfo {
				return ReceiveInfo{Peer: 0, Protection: ChannelPlaintext}
			},
			wantErr: ErrUnauthenticatedTransport,
		},
		{
			name:        "sender identity mismatch",
			payloadType: "test.direct.plain",
			to:          1,
			info: func(env Envelope) ReceiveInfo {
				return ReceiveInfo{Peer: 3, Protection: ChannelPlaintext}
			},
			wantErr: ErrSenderIdentityMismatch,
		},
		{
			name:        "wrong recipient",
			payloadType: "test.direct.plain",
			to:          3,
			wantErr:     ErrWrongRecipient,
		},
		{
			name:        "broadcast sent as direct-only payload",
			payloadType: "test.direct.plain",
			to:          0,
			wantErr:     ErrExpectedDirectMessage,
		},
		{
			name:        "direct sent as broadcast-only payload",
			payloadType: "test.broadcast.plain",
			to:          1,
			wantErr:     ErrExpectedBroadcastMessage,
		},
		{
			name:        "missing confidentiality",
			payloadType: "test.direct.confidential",
			to:          1,
			wantErr:     ErrMissingConfidentiality,
		},
		{
			name:        "unexpected confidentiality",
			payloadType: "test.direct.plain",
			to:          1,
			info: func(env Envelope) ReceiveInfo {
				return ReceiveInfo{Peer: env.From, Protection: ChannelConfidential}
			},
			wantErr: ErrUnexpectedConfidentiality,
		},
		{
			name:        "unknown payload policy",
			payloadType: "test.unknown.type",
			to:          1,
			wantErr:     ErrUnknownPayloadPolicy,
		},
		{
			name:        "missing broadcast certificate",
			payloadType: "test.broadcast.cert",
			to:          0,
			wantErr:     ErrMissingBroadcastCertificate,
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newGuardTestEnv(t)
			e := env.envelope(t, tc.payloadType, tc.to)
			if tc.mutate != nil {
				tc.mutate(t, env, &e)
			}
			info := ReceiveInfo{}
			if tc.info != nil {
				info = tc.info(e)
			}

			err := env.guard.Validate(env.inbound(e, info, nil))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
			} else if err == nil {
				t.Fatal("expected validation to reject")
			}
			if got := guardReplayCacheEntries(t, env.guard); got != 0 {
				t.Fatalf("rejected envelope stored %d replay cache entries", got)
			}
		})
	}
}

func TestGuardDropsDuplicate(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	in := env.inbound(e, ReceiveInfo{}, nil)
	if err := env.guard.Validate(in); err != nil {
		t.Fatalf("first validation should pass, got %v", err)
	}
	// Second delivery of the same message returns ErrDuplicateMessage so
	// callers can drop it immediately without further processing.
	if err := env.guard.Validate(in); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("duplicate should return ErrDuplicateMessage, got %v", err)
	}
}

func TestGuardAcceptsValidDirectMessage(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	if err := env.guard.Validate(env.inbound(e, ReceiveInfo{}, nil)); err != nil {
		t.Fatalf("valid direct message should pass, got %v", err)
	}
}

func TestGuardAcceptsValidBroadcastMessage(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.broadcast.plain", 0)
	if err := env.guard.Validate(env.inbound(e, ReceiveInfo{}, nil)); err != nil {
		t.Fatalf("valid broadcast message should pass, got %v", err)
	}
}

func TestGuardAcceptsValidConfidentialMessage(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.confidential", 1)
	info := ReceiveInfo{Peer: e.From, Protection: ChannelConfidential}
	if err := env.guard.Validate(env.inbound(e, info, nil)); err != nil {
		t.Fatalf("valid confidential message should pass, got %v", err)
	}
}

func TestGuardAcceptsOptionalConfidentialityOnPlaintext(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.optional", 1)
	// Optional confidentiality should accept plaintext delivery.
	if err := env.guard.Validate(env.inbound(e, ReceiveInfo{}, nil)); err != nil {
		t.Fatalf("optional confidentiality on plaintext should pass, got %v", err)
	}
}

func TestGuardAcceptsOptionalConfidentialityOnConfidential(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.optional", 1)
	info := ReceiveInfo{Peer: e.From, Protection: ChannelConfidential}
	// Optional confidentiality should also accept confidential delivery.
	if err := env.guard.Validate(env.inbound(e, info, nil)); err != nil {
		t.Fatalf("optional confidentiality on confidential should pass, got %v", err)
	}
}

func TestGuardAcceptsBroadcastWithValidCertificate(t *testing.T) {
	t.Parallel()
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
		EnvelopeDigest: e.Digest(),
		Recipients:     PartySet{1, 2, 3},
		Acks: []BroadcastAck{
			{Party: 1, PayloadHash: payloadHash, EnvelopeDigest: e.Digest()},
			{Party: 2, PayloadHash: payloadHash, EnvelopeDigest: e.Digest()},
			{Party: 3, PayloadHash: payloadHash, EnvelopeDigest: e.Digest()},
		},
	}
	if err := env.guard.Validate(env.inbound(e, ReceiveInfo{}, cert)); err != nil {
		t.Fatalf("valid certificate should pass, got %v", err)
	}
}

func TestBroadcastRejectsIncompleteAckSet(t *testing.T) {
	t.Parallel()
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
		EnvelopeDigest: e.Digest(),
		Recipients:     PartySet{1, 2, 3},
		Acks: []BroadcastAck{
			{Party: 1, PayloadHash: payloadHash, EnvelopeDigest: e.Digest()},
			// Missing party 2 and 3
		},
	}
	err := env.guard.Validate(env.inbound(e, ReceiveInfo{}, cert))
	if !errors.Is(err, ErrInvalidBroadcastCertificate) {
		t.Fatalf("expected ErrInvalidBroadcastCertificate, got %v", err)
	}
}

func TestBroadcastRejectsWrongDigestAck(t *testing.T) {
	t.Parallel()
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
		EnvelopeDigest: e.Digest(),
		Recipients:     PartySet{1, 2, 3},
		Acks: []BroadcastAck{
			{Party: 1, PayloadHash: payloadHash, EnvelopeDigest: e.Digest()},
			{Party: 2, PayloadHash: wrongHash, EnvelopeDigest: e.Digest()}, // wrong payload hash
			{Party: 3, PayloadHash: payloadHash, EnvelopeDigest: e.Digest()},
		},
	}
	err := env.guard.Validate(env.inbound(e, ReceiveInfo{}, cert))
	if !errors.Is(err, ErrInvalidBroadcastCertificate) {
		t.Fatalf("expected ErrInvalidBroadcastCertificate, got %v", err)
	}
}

// --- ValidateEnvelopePolicy tests ---

func TestValidateEnvelopePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		env        Envelope
		self       PartyID
		protection ChannelProtection
		wantErr    error
	}{
		{
			name:    "unknown payload type rejects",
			env:     testEnvelope("test-proto", 1, "test.unknown.payload", 2, 0),
			self:    1,
			wantErr: ErrUnknownPayloadPolicy,
		},
		{
			name:    "direct policy sent as broadcast rejects",
			env:     testEnvelope("test-proto", 1, "test.direct.confidential", 2, 0),
			self:    1,
			wantErr: ErrExpectedDirectMessage,
		},
		{
			name:    "broadcast policy sent as direct rejects",
			env:     testEnvelope("test-proto", 1, "test.broadcast.plain", 2, 1),
			self:    1,
			wantErr: ErrExpectedBroadcastMessage,
		},
		{
			name:    "wrong direct recipient rejects",
			env:     testEnvelope("test-proto", 1, "test.direct.confidential", 2, 3),
			self:    1,
			wantErr: ErrWrongRecipient,
		},
		{
			name:       "missing confidentiality rejects",
			env:        testEnvelope("test-proto", 1, "test.direct.confidential", 2, 1),
			self:       1,
			protection: ChannelPlaintext,
			wantErr:    ErrMissingConfidentiality,
		},
		{
			name:       "unexpected confidentiality rejects",
			env:        testEnvelope("test-proto", 1, "test.direct.plain", 2, 1),
			self:       1,
			protection: ChannelConfidential,
			wantErr:    ErrUnexpectedConfidentiality,
		},
		{
			name:       "direct confidential accepts",
			env:        testEnvelope("test-proto", 1, "test.direct.confidential", 2, 1),
			self:       1,
			protection: ChannelConfidential,
		},
		{
			name: "broadcast accepts",
			env:  testEnvelope("test-proto", 1, "test.broadcast.plain", 2, 0),
			self: 1,
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := tc.env
			protection := tc.protection
			if protection == ChannelProtectionUnknown {
				protection = ChannelPlaintext
			}
			in := InboundEnvelope{
				env: env,
				receiveInfo: ReceiveInfo{
					Peer:       env.From,
					Protection: protection,
				},
			}
			err := ValidateEnvelopePolicy(in, tc.self, testPolicySet())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

// testEnvelope builds a minimal envelope for policy testing.
func testEnvelope(protocol ProtocolID, round uint8, payloadType PayloadType, from, to PartyID) Envelope {
	return Envelope{
		Protocol:    protocol,
		SessionID:   SessionID{1},
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     []byte("test"),
	}
}

func TestMustNewPolicySetPanicsOnDuplicate(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustNewPolicySet should panic on duplicate")
		}
	}()
	MustNewPolicySet(
		DeliveryPolicy{Protocol: "p", Round: 1, PayloadType: "a", Mode: DeliveryDirect},
		DeliveryPolicy{Protocol: "p", Round: 1, PayloadType: "a", Mode: DeliveryDirect},
	)
}

func TestMustNewPolicySetPanicsOnBroadcastWithoutConsistency(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustNewPolicySet should panic when broadcast lacks consistency")
		}
	}()
	MustNewPolicySet(
		DeliveryPolicy{Protocol: "p", Round: 1, PayloadType: "b", Mode: DeliveryBroadcast, BroadcastConsistency: BroadcastConsistencyNone},
	)
}

func TestPolicySetEntriesReturnsCopy(t *testing.T) {
	t.Parallel()
	ps := testPolicySet()
	entries := ps.Entries()
	// Mutating the returned slice must not affect the policy set.
	entries[0] = DeliveryPolicy{}
	entries2 := ps.Entries()
	if entries2[0].Protocol == "" {
		t.Fatal("Entries() returned a shared mutable slice")
	}
}

func TestPolicySetMatchRejectsNilIndex(t *testing.T) {
	t.Parallel()
	ps := PolicySet{}
	_, err := ps.Match("test", 1, "payload")
	if !errors.Is(err, ErrUnknownPayloadPolicy) {
		t.Fatalf("expected ErrUnknownPayloadPolicy for uninitialized PolicySet, got %v", err)
	}
}

func TestValidateBroadcastConsistency(t *testing.T) {
	t.Parallel()
	// testPolicySet has a broadcast policy without consistency → ValidateBroadcastConsistency should fail.
	ps := testPolicySet()
	if err := ps.ValidateBroadcastConsistency(); err == nil {
		t.Fatal("testPolicySet has a broadcast policy without BroadcastConsistencyRequired — should fail validation")
	}
	// Create a valid policy set with all broadcasts requiring consistency.
	valid, err := NewPolicySet(
		DeliveryPolicy{Protocol: "p", Round: 1, PayloadType: "direct", Mode: DeliveryDirect},
		DeliveryPolicy{Protocol: "p", Round: 1, PayloadType: "bc", Mode: DeliveryBroadcast, BroadcastConsistency: BroadcastConsistencyRequired},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := valid.ValidateBroadcastConsistency(); err != nil {
		t.Fatalf("all broadcasts require consistency — should pass: %v", err)
	}
}

func TestTestGuardConfig(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	cfg := TestGuardConfig(1, PartySet{1, 2}, "test-proto", sid, testPolicySet())
	if cfg.Self != 1 {
		t.Fatal("Self mismatch")
	}
	if cfg.Cache == nil {
		t.Fatal("Cache must be non-nil")
	}
	if cfg.Parties[0] != 1 {
		t.Fatal("Parties mismatch")
	}
}

func TestBuildGuardRejectsNilAckVerifier(t *testing.T) {
	t.Parallel()
	cfg := GuardConfig{
		Self:      1,
		Parties:   PartySet{1, 2, 3},
		Protocol:  "test-proto",
		SessionID: testSessionID(t),
		Policies:  testPolicySet(),
		Cache:     NewInMemoryReplayCache(),
		// AckVerifier intentionally nil
	}
	_, err := cfg.BuildGuard()
	if !errors.Is(err, ErrMissingAckVerifier) {
		t.Fatalf("expected ErrMissingAckVerifier, got %v", err)
	}
}

func TestBuildGuardSucceedsWithValidConfig(t *testing.T) {
	t.Parallel()
	cfg := GuardConfig{
		Self:        1,
		Parties:     PartySet{1, 2, 3},
		Protocol:    "test-proto",
		SessionID:   testSessionID(t),
		Policies:    testPolicySet(),
		Cache:       NewInMemoryReplayCache(),
		AckVerifier: NewInMemoryAckVerifier(nil),
	}
	g, err := cfg.BuildGuard()
	if err != nil {
		t.Fatalf("BuildGuard failed: %v", err)
	}
	if g == nil {
		t.Fatal("BuildGuard returned nil guard")
	}
	if g.AckVerifier == nil {
		t.Fatal("BuildGuard did not wire AckVerifier")
	}
}

func TestRequireEnvelopeGuard(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	guard := NewTestEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, testPolicySet())
	if err := RequireEnvelopeGuard(guard, "test-proto", sid, 1); err != nil {
		t.Fatalf("RequireEnvelopeGuard rejected valid guard: %v", err)
	}

	t.Run("nil", func(t *testing.T) {
		err := RequireEnvelopeGuard(nil, "test-proto", sid, 1)
		if !errors.Is(err, ErrMissingEnvelopeGuard) {
			t.Fatalf("expected ErrMissingEnvelopeGuard, got %v", err)
		}
	})

	t.Run("wrong protocol", func(t *testing.T) {
		if err := RequireEnvelopeGuard(guard, "wrong-proto", sid, 1); err == nil {
			t.Fatal("expected protocol mismatch")
		}
	})

	t.Run("wrong session", func(t *testing.T) {
		if err := RequireEnvelopeGuard(guard, "test-proto", testSessionID(t), 1); err == nil {
			t.Fatal("expected session mismatch")
		}
	})

	t.Run("wrong self", func(t *testing.T) {
		if err := RequireEnvelopeGuard(guard, "test-proto", sid, 2); err == nil {
			t.Fatal("expected self mismatch")
		}
	})

	t.Run("empty policies", func(t *testing.T) {
		bad := *guard
		bad.Policies = PolicySet{}
		if err := RequireEnvelopeGuard(&bad, "test-proto", sid, 1); err == nil {
			t.Fatal("expected empty policy set rejection")
		}
	})

	t.Run("nil replay cache", func(t *testing.T) {
		bad := *guard
		bad.ReplayCache = nil
		err := RequireEnvelopeGuard(&bad, "test-proto", sid, 1)
		if !errors.Is(err, ErrMissingReplayCache) {
			t.Fatalf("expected ErrMissingReplayCache, got %v", err)
		}
	})
}

func TestValidateInboundNilGuard(t *testing.T) {
	t.Parallel()
	env := testEnvelope("test-proto", 1, "test.direct.plain", 2, 1)
	in := InboundEnvelope{
		env: env,
		receiveInfo: ReceiveInfo{
			Peer:       env.From,
			Protection: ChannelPlaintext,
		},
	}
	err := ValidateInbound(nil, in, "test-proto", SessionID{1}, PartySet{1, 2, 3}, 1)
	if !errors.Is(err, ErrMissingEnvelopeGuard) {
		t.Fatalf("expected ErrMissingEnvelopeGuard, got %v", err)
	}
}

func TestValidateInboundWrongProtocol(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	err := ValidateInbound(env.guard, env.inbound(e, ReceiveInfo{}, nil), "wrong-proto", env.sessionID, PartySet{1, 2, 3}, 1)
	if err == nil {
		t.Fatal("expected error for wrong protocol")
	}
}

func TestValidateInboundWrongSession(t *testing.T) {
	t.Parallel()
	env := newGuardTestEnv(t)
	e := env.envelope(t, "test.direct.plain", 1)
	wrongSID := testSessionID(t)
	err := ValidateInbound(env.guard, env.inbound(e, ReceiveInfo{}, nil), "test-proto", wrongSID, PartySet{1, 2, 3}, 1)
	if err == nil {
		t.Fatal("expected error for wrong session")
	}
}

func TestOpenEnvelopeClonesPayload(t *testing.T) {
	t.Parallel()
	session, _ := NewSessionID(nil)
	payload := []byte("original")
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
		Payload:     payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEnvelope(raw, ReceiveInfo{Peer: 1, Protection: ChannelPlaintext})
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the original payload — the opened payload must be unaffected.
	payload[0] ^= 0xff
	if bytes.Equal(opened.Payload(), payload) {
		t.Fatal("OpenEnvelope payload is not cloned from the raw input")
	}
	// Mutate the returned payload — subsequent access must be unaffected.
	got := opened.Payload()
	got[0] ^= 0xff
	if bytes.Equal(opened.Payload(), got) {
		t.Fatal("Payload() does not return a copy on subsequent calls")
	}
}

func TestInboundEnvelopeAccessorsReturnCopies(t *testing.T) {
	t.Parallel()
	session, _ := NewSessionID(nil)
	payload := []byte("test-payload")
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
		Payload:     payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ackSig := []byte("ack-signature")
	cert, err := NewBroadcastCertificate(env, PartySet{1}, []BroadcastAck{{
		Party:          1,
		PayloadHash:    sha256Sum(env.Payload),
		EnvelopeDigest: env.Digest(),
		Signature:      ackSig,
	}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEnvelope(raw, ReceiveInfo{Peer: 1, Protection: ChannelPlaintext}, WithBroadcastCertificate(cert))
	if err != nil {
		t.Fatal(err)
	}

	// Envelope() returns a deep copy — mutating the returnee must not affect the original.
	clone1 := opened.Envelope()
	clone1.Payload[0] ^= 0xff
	clone2 := opened.Envelope()
	if bytes.Equal(clone1.Payload, clone2.Payload) {
		t.Fatal("Envelope() does not return an independent deep copy")
	}

	// Payload() returns a copy.
	p1 := opened.Payload()
	p1[0] ^= 0xff
	p2 := opened.Payload()
	if bytes.Equal(p1, p2) {
		t.Fatal("Payload() does not return an independent copy")
	}

	// BroadcastCertificate() returns a deep copy.
	bc1 := opened.BroadcastCertificate()
	bc1.Acks[0].Signature[0] ^= 0xff
	bc2 := opened.BroadcastCertificate()
	if bytes.Equal(bc1.Acks[0].Signature, bc2.Acks[0].Signature) {
		t.Fatal("BroadcastCertificate() does not return an independent deep copy")
	}
}

func TestOpenEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	session, _ := NewSessionID(nil)
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEnvelope(raw, ReceiveInfo{
		Peer:       1,
		Protection: ChannelPlaintext,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := opened.Envelope()
	if base.Protocol != env.Protocol || base.SessionID != env.SessionID {
		t.Fatal("OpenEnvelope field mismatch")
	}
}

func TestOpenEnvelopeRejectsMalformed(t *testing.T) {
	t.Parallel()
	if _, err := OpenEnvelope([]byte("not-valid"), ReceiveInfo{Peer: 1, Protection: ChannelPlaintext}); err == nil {
		t.Fatal("OpenEnvelope accepted malformed input")
	}
}

func TestOpenEnvelopeRejectsInvalidReceiveInfo(t *testing.T) {
	t.Parallel()
	session, _ := NewSessionID(nil)
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		info ReceiveInfo
		want error
	}{
		{name: "zero peer", info: ReceiveInfo{Protection: ChannelPlaintext}, want: ErrUnauthenticatedTransport},
		{name: "unknown protection", info: ReceiveInfo{Peer: 1}, want: ErrMissingChannelProtection},
		{name: "undefined protection", info: ReceiveInfo{Peer: 1, Protection: ChannelProtection(255)}, want: ErrInvalidChannelProtection},
		{name: "sender mismatch", info: ReceiveInfo{Peer: 2, Protection: ChannelPlaintext}, want: ErrSenderIdentityMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OpenEnvelope(raw, tc.info)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestMarshalEnvelopeWithLimits(t *testing.T) {
	t.Parallel()
	session, _ := NewSessionID(nil)
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := EnvelopeLimits{
		MaxBytes:             65536,
		MaxProtocolNameBytes: 32,
		MaxPayloadTypeBytes:  64,
		MaxPayloadBytes:      65536,
	}
	raw, err := MarshalEnvelopeWithLimits(env, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("MarshalEnvelopeWithLimits returned empty")
	}
}

func TestMarshalEnvelopeWithLimitsExceeded(t *testing.T) {
	t.Parallel()
	session, _ := NewSessionID(nil)
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
		Payload:     make([]byte, 100),
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := EnvelopeLimits{
		MaxBytes:             10,
		MaxProtocolNameBytes: 32,
		MaxPayloadTypeBytes:  64,
		MaxPayloadBytes:      10,
	}
	if _, err := MarshalEnvelopeWithLimits(env, limits); err == nil {
		t.Fatal("MarshalEnvelopeWithLimits should reject oversized envelope")
	}
}
