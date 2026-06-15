package tss

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Transport abstracts the network layer used to deliver protocol envelopes.
// Implementations receive raw wire bytes, authenticate the peer, classify the
// actual channel protection, and return an InboundEnvelope opened with ReceiveInfo.
type Transport interface {
	// Send delivers a direct (point-to-point) envelope to its recipient.
	Send(ctx context.Context, env Envelope) error

	// Broadcast delivers an envelope to all parties.
	Broadcast(ctx context.Context, env Envelope) error

	// Receive blocks until the next envelope is available and returns it
	// with transport-verified receive facts bound to the wire envelope.
	Receive(ctx context.Context) (InboundEnvelope, error)
}

// InMemoryTransport is a reference implementation of Transport that uses
// Go channels for in-process message delivery. Each party gets its own
// transport instance. Messages are opened with authenticated ReceiveInfo.
//
// Direct messages are delivered only to the addressed recipient. Broadcast
// messages are delivered to all parties.
//
// Broadcast certificates are NOT generated automatically.
type InMemoryTransport struct {
	self     PartyID
	parties  PartySet
	policies PolicySet
	inbox    chan InboundEnvelope
	outboxes map[PartyID]chan<- InboundEnvelope
	mu       sync.RWMutex
}

// NewInMemoryTransport creates a transport for one party.
func NewInMemoryTransport(self PartyID, parties PartySet, policies PolicySet) *InMemoryTransport {
	return &InMemoryTransport{
		self:     self,
		parties:  parties.Clone(),
		policies: policies,
		inbox:    make(chan InboundEnvelope, 256),
		outboxes: make(map[PartyID]chan<- InboundEnvelope),
	}
}

// ConnectOutbox registers the outbox channel for a remote party.
// In a real deployment this would be a network connection.
func (t *InMemoryTransport) ConnectOutbox(party PartyID, outbox chan<- InboundEnvelope) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outboxes[party] = outbox
}

// Inbox returns the receive channel for this transport.
func (t *InMemoryTransport) Inbox() <-chan InboundEnvelope {
	return t.inbox
}

// Parties returns the party set for this transport instance.
func (t *InMemoryTransport) Parties() PartySet {
	return t.parties.Clone()
}

// Send delivers a direct envelope to the addressed recipient.
func (t *InMemoryTransport) Send(_ context.Context, env Envelope) error {
	if env.To == 0 {
		return fmt.Errorf("%w: cannot Send to broadcast address", ErrExpectedDirectMessage)
	}

	policy, err := t.policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return err
	}
	if policy.Mode != DeliveryDirect {
		return fmt.Errorf("%w: %s", ErrExpectedDirectMessage, env.PayloadType)
	}

	t.mu.RLock()
	outbox, ok := t.outboxes[env.To]
	t.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no route to party %d", env.To)
	}

	inbound, err := openInMemoryEnvelope(env, env.From, protectionFromPolicy(policy), "inmemory", nil)
	if err != nil {
		return err
	}

	select {
	case outbox <- inbound:
		return nil
	default:
		return fmt.Errorf("outbox full for party %d", env.To)
	}
}

// Broadcast delivers an envelope to all parties.
func (t *InMemoryTransport) Broadcast(_ context.Context, env Envelope) error {
	if env.To != 0 {
		return fmt.Errorf("%w: cannot Broadcast to direct address", ErrExpectedBroadcastMessage)
	}

	policy, err := t.policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return err
	}
	if policy.Mode != DeliveryBroadcast {
		return fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, env.PayloadType)
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, id := range t.parties {
		if id == t.self {
			continue
		}
		outbox, ok := t.outboxes[id]
		if !ok {
			return fmt.Errorf("no route to party %d", id)
		}
		inbound, err := openInMemoryEnvelope(env, env.From, protectionFromPolicy(policy), "inmemory", nil)
		if err != nil {
			return err
		}
		select {
		case outbox <- inbound:
		default:
			return fmt.Errorf("outbox full for party %d", id)
		}
	}
	return nil
}

// Receive returns the next envelope from the inbox.
func (t *InMemoryTransport) Receive(ctx context.Context) (InboundEnvelope, error) {
	select {
	case env := <-t.inbox:
		return env, nil
	case <-ctx.Done():
		return InboundEnvelope{}, ctx.Err()
	}
}

func protectionFromPolicy(policy DeliveryPolicy) ChannelProtection {
	if policy.Confidentiality == ConfidentialityRequired {
		return ChannelConfidential
	}
	return ChannelPlaintext
}

func openInMemoryEnvelope(env Envelope, peer PartyID, protection ChannelProtection, channelID string, cert *BroadcastCertificate) (InboundEnvelope, error) {
	raw, err := env.MarshalBinary()
	if err != nil {
		return InboundEnvelope{}, err
	}
	return OpenEnvelope(raw, ReceiveInfo{
		Peer:       peer,
		Protection: protection,
		ChannelID:  channelID,
		PeerKeyID:  fmt.Sprintf("party-%d", peer),
		ReceivedAt: time.Now(),
	}, WithBroadcastCertificate(cert))
}

// AttackMode specifies a type of transport-layer attack for testing.
type AttackMode uint8

const (
	// AttackSenderSpoof opens an envelope with ReceiveInfo.Peer different from Envelope.From.
	AttackSenderSpoof AttackMode = iota
	// AttackPlaintextConfidential reports plaintext delivery for confidential-required messages.
	AttackPlaintextConfidential
	// AttackReplay sends the same envelope twice.
	AttackReplay
	// AttackWrongRecipient delivers a direct message to the wrong party.
	AttackWrongRecipient
	// AttackBroadcastEquivocation sends different payloads to different parties.
	AttackBroadcastEquivocation
	// AttackDropAck fails to include an ack in the broadcast certificate.
	AttackDropAck
	// AttackInvalidAckSignature includes an ack with an invalid signature.
	AttackInvalidAckSignature
)

// MaliciousTransport wraps an InMemoryTransport and applies a specified
// transport-layer attack for security testing. Every attack mode must be
// caught by EnvelopeGuard.Validate before reaching the protocol handler.
type MaliciousTransport struct {
	inner  *InMemoryTransport
	mode   AttackMode
	replay *Envelope // stored envelope for AttackReplay; shared by Send and Broadcast
	mu     sync.Mutex
}

// NewMaliciousTransport creates a transport that applies the given attack.
func NewMaliciousTransport(inner *InMemoryTransport, mode AttackMode) *MaliciousTransport {
	return &MaliciousTransport{inner: inner, mode: mode}
}

// Send applies the attack mode and delegates to the inner transport.
func (m *MaliciousTransport) Send(ctx context.Context, env Envelope) error {
	modified := env.Clone()
	switch m.mode {
	case AttackSenderSpoof:
		return m.sendWithReceiveFacts(modified, 999, ChannelConfidential, "inmemory-spoof")
	case AttackPlaintextConfidential:
		return m.sendWithReceiveFacts(modified, modified.From, ChannelPlaintext, "inmemory-plaintext")
	case AttackReplay:
		m.mu.Lock()
		if m.replay != nil {
			replay := *m.replay
			m.mu.Unlock()
			return m.inner.Send(ctx, replay)
		}
		m.replay = &modified
		m.mu.Unlock()
		if err := m.inner.Send(ctx, modified); err != nil {
			return err
		}
		// Send the same envelope again
		return m.inner.Send(ctx, modified)
	case AttackWrongRecipient:
		// Deliver to the wrong recipient (strip To, send as broadcast or swap To)
		modified.To = 999
	}
	return m.inner.Send(ctx, modified)
}

func (m *MaliciousTransport) sendWithReceiveFacts(env Envelope, peer PartyID, protection ChannelProtection, channelID string) error {
	if env.To == 0 {
		return fmt.Errorf("%w: cannot Send to broadcast address", ErrExpectedDirectMessage)
	}
	policy, err := m.inner.policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return err
	}
	if policy.Mode != DeliveryDirect {
		return fmt.Errorf("%w: %s", ErrExpectedDirectMessage, env.PayloadType)
	}
	m.inner.mu.RLock()
	outbox, ok := m.inner.outboxes[env.To]
	m.inner.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no route to party %d", env.To)
	}
	inbound, err := openInMemoryEnvelope(env, peer, protection, channelID, nil)
	if err != nil {
		return err
	}
	select {
	case outbox <- inbound:
		return nil
	default:
		return fmt.Errorf("outbox full for party %d", env.To)
	}
}

// Broadcast applies the attack mode and delegates to the inner transport.
func (m *MaliciousTransport) Broadcast(ctx context.Context, env Envelope) error {
	switch m.mode {
	case AttackBroadcastEquivocation:
		// Send the original payload to the first party and a tampered
		// version (with a different payload) to all other parties.
		// This simulates a sender equivocating on broadcast content.
		return m.broadcastEquivocation(env)
	case AttackReplay:
		modified := env.Clone()
		m.mu.Lock()
		if m.replay != nil {
			replay := *m.replay
			m.mu.Unlock()
			return m.inner.Broadcast(ctx, replay)
		}
		m.replay = &modified
		m.mu.Unlock()
		if err := m.inner.Broadcast(ctx, modified); err != nil {
			return err
		}
		// Broadcast the same envelope again to simulate replay.
		return m.inner.Broadcast(ctx, modified)
	default:
	}
	return m.inner.Broadcast(ctx, env.Clone())
}

func (m *MaliciousTransport) broadcastEquivocation(env Envelope) error {
	policy, err := m.inner.policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return err
	}
	if policy.Mode != DeliveryBroadcast {
		return fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, env.PayloadType)
	}

	// Build a tampered clone with a different payload.
	tampered := env.Clone()
	if len(tampered.Payload) > 0 {
		tampered.Payload = append([]byte(nil), tampered.Payload...)
		tampered.Payload[0] ^= 0xff // flip bits to create a different payload
	} else {
		tampered.Payload = []byte{0xde, 0xad}
	}
	// Recompute transcript hash so structural checks still pass.
	tampered = tampered.RecomputeTranscriptHash()

	m.inner.mu.RLock()
	defer m.inner.mu.RUnlock()

	firstSent := false
	for _, id := range m.inner.parties {
		if id == m.inner.self {
			continue
		}
		outbox, ok := m.inner.outboxes[id]
		if !ok {
			return fmt.Errorf("no route to party %d", id)
		}
		var delivered Envelope
		if !firstSent {
			delivered = env.Clone()
			firstSent = true
		} else {
			delivered = tampered.Clone()
		}
		inbound, err := openInMemoryEnvelope(delivered, env.From, protectionFromPolicy(policy), "inmemory-equivocation", nil)
		if err != nil {
			return err
		}
		select {
		case outbox <- inbound:
		default:
			return fmt.Errorf("outbox full for party %d", id)
		}
	}
	return nil
}

// Receive delegates to the inner transport.
func (m *MaliciousTransport) Receive(ctx context.Context) (InboundEnvelope, error) {
	return m.inner.Receive(ctx)
}
