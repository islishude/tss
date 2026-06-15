package tss

import (
	"context"
	"errors"
	"testing"
)

func inboundForTransportTest(env Envelope, protection ChannelProtection) InboundEnvelope {
	return InboundEnvelope{
		env: env.Clone(),
		receiveInfo: ReceiveInfo{
			Peer:       env.From,
			Protection: protection,
			ChannelID:  "test",
			PeerKeyID:  "party",
		},
	}
}

func TestInMemoryTransportSendAndReceive(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	policies := testPolicySet()
	party1 := NewInMemoryTransport(1, PartySet{1, 2}, policies)
	party2 := NewInMemoryTransport(2, PartySet{1, 2}, policies)

	// Cross-connect outboxes using the inbox channels
	party1.ConnectOutbox(2, party2.inbox)
	party2.ConnectOutbox(1, party1.inbox)

	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test-proto",
		Version:     Version,
		SessionID:   sid,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "test.direct.plain",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := party1.Send(ctx, env); err != nil {
		t.Fatalf("send: %v", err)
	}

	received, err := party2.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	info := received.ReceiveInfo()
	if info.Peer != 1 {
		t.Fatalf("ReceiveInfo.Peer must be 1, got %d", info.Peer)
	}
	if got := received.Envelope().From; got != 1 {
		t.Fatalf("Envelope.From must be 1, got %d", got)
	}
}

func TestInMemoryTransportConfidentialityFlag(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	policies := testPolicySet()
	party1 := NewInMemoryTransport(1, PartySet{1, 2}, policies)
	party2 := NewInMemoryTransport(2, PartySet{1, 2}, policies)
	party1.ConnectOutbox(2, party2.inbox)
	party2.ConnectOutbox(1, party1.inbox)

	// Send a confidential-required message
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test-proto",
		Version:     Version,
		SessionID:   sid,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "test.direct.confidential",
		Payload:     []byte("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := party1.Send(ctx, env); err != nil {
		t.Fatalf("send: %v", err)
	}

	received, err := party2.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	if got := received.ReceiveInfo().Protection; got != ChannelConfidential {
		t.Fatalf("confidential-required message must report ChannelConfidential, got %d", got)
	}
}

func TestMaliciousTransportSenderSpoof(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	policies := testPolicySet()
	inner := NewInMemoryTransport(1, PartySet{1, 2}, policies)
	inner.ConnectOutbox(2, make(chan InboundEnvelope, 1)) // discard output
	mal := NewMaliciousTransport(inner, AttackSenderSpoof)

	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test-proto",
		Version:     Version,
		SessionID:   sid,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "test.direct.confidential",
		Payload:     []byte("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = mal.Send(context.Background(), env)
	if !errors.Is(err, ErrSenderIdentityMismatch) {
		t.Fatalf("expected ErrSenderIdentityMismatch, got %v", err)
	}
}

func TestMaliciousTransportPlaintextConfidential(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	policies := testPolicySet()
	inner := NewInMemoryTransport(1, PartySet{1, 2}, policies)
	outbox := make(chan InboundEnvelope, 1)
	inner.ConnectOutbox(2, outbox)
	mal := NewMaliciousTransport(inner, AttackPlaintextConfidential)

	env, _ := NewEnvelope(EnvelopeInput{
		Protocol:    "test-proto",
		Version:     Version,
		SessionID:   sid,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "test.direct.confidential",
		Payload:     []byte("secret"),
	})
	if err := mal.Send(context.Background(), env); err != nil {
		t.Fatalf("send: %v", err)
	}
	received := <-outbox
	if got := received.ReceiveInfo().Protection; got != ChannelPlaintext {
		t.Fatalf("expected ChannelPlaintext, got %d", got)
	}
}

// TestTransportSecurityIntegration verifies that every MaliciousTransport attack
// mode is caught by EnvelopeGuard.Validate before reaching the protocol handler.
func TestTransportSecurityIntegration(t *testing.T) {
	t.Parallel()
	policies := testPolicySet()

	t.Run("valid message passes guard", func(t *testing.T) {
		sid := testSessionID(t)
		guard, err := NewEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, policies, NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		env, _ := NewEnvelope(EnvelopeInput{
			Protocol: "test-proto", Version: Version, SessionID: sid,
			Round: 1, From: 2, To: 1, PayloadType: "test.direct.plain",
			Payload: []byte("hello"),
		})
		if err := guard.Validate(inboundForTransportTest(env, ChannelPlaintext)); err != nil {
			t.Fatalf("valid message should pass: %v", err)
		}
	})

	t.Run("rejects unauthenticated transport", func(t *testing.T) {
		sid := testSessionID(t)
		guard, _ := NewEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, policies, NewInMemoryReplayCache())
		env, _ := NewEnvelope(EnvelopeInput{
			Protocol: "test-proto", Version: Version, SessionID: sid,
			Round: 1, From: 2, To: 1, PayloadType: "test.direct.plain",
			Payload: []byte("hello"),
		})
		in := InboundEnvelope{env: env.Clone(), receiveInfo: ReceiveInfo{Protection: ChannelPlaintext}}
		if !errors.Is(guard.Validate(in), ErrUnauthenticatedTransport) {
			t.Fatal("should reject unauthenticated transport")
		}
	})

	t.Run("rejects sender spoofing", func(t *testing.T) {
		sid := testSessionID(t)
		guard, _ := NewEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, policies, NewInMemoryReplayCache())
		env, _ := NewEnvelope(EnvelopeInput{
			Protocol: "test-proto", Version: Version, SessionID: sid,
			Round: 1, From: 2, To: 1, PayloadType: "test.direct.plain",
			Payload: []byte("hello"),
		})
		in := InboundEnvelope{env: env.Clone(), receiveInfo: ReceiveInfo{Peer: 3, Protection: ChannelPlaintext}}
		if !errors.Is(guard.Validate(in), ErrSenderIdentityMismatch) {
			t.Fatal("should reject sender spoofing")
		}
	})

	t.Run("rejects plaintext confidential", func(t *testing.T) {
		sid := testSessionID(t)
		guard, _ := NewEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, policies, NewInMemoryReplayCache())
		env, _ := NewEnvelope(EnvelopeInput{
			Protocol: "test-proto", Version: Version, SessionID: sid,
			Round: 1, From: 2, To: 1, PayloadType: "test.direct.confidential",
			Payload: []byte("secret"),
		})
		if !errors.Is(guard.Validate(inboundForTransportTest(env, ChannelPlaintext)), ErrMissingConfidentiality) {
			t.Fatal("should reject plaintext confidential")
		}
	})

	t.Run("rejects replay", func(t *testing.T) {
		sid := testSessionID(t)
		guard, _ := NewEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, policies, NewInMemoryReplayCache())
		env, _ := NewEnvelope(EnvelopeInput{
			Protocol: "test-proto", Version: Version, SessionID: sid,
			Round: 1, From: 2, To: 1, PayloadType: "test.direct.plain",
			Payload: []byte("hello"),
		})
		in := inboundForTransportTest(env, ChannelPlaintext)
		if err := guard.Validate(in); err != nil {
			t.Fatalf("first pass: %v", err)
		}
		if err := guard.Validate(in); !errors.Is(err, ErrDuplicateMessage) {
			t.Fatalf("duplicate should return ErrDuplicateMessage, got %v", err)
		}
	})

	t.Run("rejects wrong recipient", func(t *testing.T) {
		sid := testSessionID(t)
		guard, _ := NewEnvelopeGuard(1, PartySet{1, 2, 3}, "test-proto", sid, policies, NewInMemoryReplayCache())
		env, _ := NewEnvelope(EnvelopeInput{
			Protocol: "test-proto", Version: Version, SessionID: sid,
			Round: 1, From: 2, To: 3, PayloadType: "test.direct.plain",
			Payload: []byte("hello"),
		})
		if !errors.Is(guard.Validate(inboundForTransportTest(env, ChannelPlaintext)), ErrWrongRecipient) {
			t.Fatal("should reject wrong recipient")
		}
	})
}
