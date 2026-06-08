package tss

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Transport abstracts the network layer used to deliver protocol envelopes.
// Implementations must:
//   - Set SecurityContext on received envelopes (authenticated identity, confidentiality).
//   - Attach BroadcastCertificates when the protocol policy requires consistency.
//   - Respect the protocol policy table for delivery mode and confidentiality.
type Transport interface {
	// Send delivers a direct (point-to-point) envelope to its recipient.
	Send(ctx context.Context, env Envelope) error

	// Broadcast delivers an envelope to all parties.
	Broadcast(ctx context.Context, env Envelope) error

	// Receive blocks until the next envelope is available and returns it
	// with SecurityContext populated from the transport layer.
	Receive(ctx context.Context) (Envelope, error)
}

// InMemoryTransport is a reference implementation of Transport that uses
// Go channels for in-process message delivery. Each party gets its own
// transport instance. Messages are delivered with full SecurityContext.
//
// Direct messages are delivered only to the addressed recipient. Broadcast
// messages are delivered to all parties.
//
// Broadcast certificates are NOT generated automatically — the caller must
// use BroadcastConsistency externally and attach the certificate to the
// envelope before passing it to protocol handlers.
type InMemoryTransport struct {
	self     PartyID
	parties  PartySet
	policies PolicySet
	inbox    chan Envelope
	outboxes map[PartyID]chan<- Envelope
	mu       sync.RWMutex
}

// NewInMemoryTransport creates a transport for one party.
func NewInMemoryTransport(self PartyID, parties PartySet, policies PolicySet) *InMemoryTransport {
	return &InMemoryTransport{
		self:     self,
		parties:  parties.Clone(),
		policies: policies,
		inbox:    make(chan Envelope, 256),
		outboxes: make(map[PartyID]chan<- Envelope),
	}
}

// ConnectOutbox registers the outbox channel for a remote party.
// In a real deployment this would be a network connection.
func (t *InMemoryTransport) ConnectOutbox(party PartyID, outbox chan<- Envelope) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outboxes[party] = outbox
}

// Inbox returns the receive channel for this transport.
func (t *InMemoryTransport) Inbox() <-chan Envelope {
	return t.inbox
}

// Parties returns the party set for this transport instance.
func (t *InMemoryTransport) Parties() PartySet {
	return t.parties.Clone()
}

// Send delivers a direct envelope to the addressed recipient with full
// SecurityContext.
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

	secured := env.Clone()
	secured.Security = SecurityContext{
		Authenticated:      true,
		Confidential:       policy.Confidentiality == ConfidentialityRequired,
		AuthenticatedParty: env.From,
		ChannelID:          "inmemory",
		PeerKeyID:          fmt.Sprintf("party-%d", env.From),
		ReceivedAtUnix:     time.Now().Unix(),
	}

	select {
	case outbox <- secured:
		return nil
	default:
		return fmt.Errorf("outbox full for party %d", env.To)
	}
}

// Broadcast delivers an envelope to all parties with full SecurityContext.
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
		secured := env.Clone()
		secured.Security = SecurityContext{
			Authenticated:      true,
			Confidential:       policy.Confidentiality == ConfidentialityRequired,
			AuthenticatedParty: env.From,
			ChannelID:          "inmemory",
			PeerKeyID:          fmt.Sprintf("party-%d", env.From),
			ReceivedAtUnix:     time.Now().Unix(),
		}
		select {
		case outbox <- secured:
		default:
			return fmt.Errorf("outbox full for party %d", id)
		}
	}
	return nil
}

// Receive returns the next envelope from the inbox.
func (t *InMemoryTransport) Receive(ctx context.Context) (Envelope, error) {
	select {
	case env := <-t.inbox:
		return env, nil
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
	}
}

// AttackMode specifies a type of transport-layer attack for testing.
type AttackMode uint8

const (
	// AttackSenderSpoof sets AuthenticatedParty different from Envelope.From.
	AttackSenderSpoof AttackMode = iota
	// AttackPlaintextConfidential strips the Confidential flag on confidential-required messages.
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
	replay *Envelope // stored envelope for AttackReplay
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
		modified.Security.AuthenticatedParty = 999 // mismatch
	case AttackPlaintextConfidential:
		modified.Security.Confidential = false // strip confidentiality
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

// Broadcast applies the attack mode and delegates to the inner transport.
func (m *MaliciousTransport) Broadcast(ctx context.Context, env Envelope) error {
	switch m.mode {
	case AttackBroadcastEquivocation:
		// Send the original payload to the first party and a tampered
		// version (with a different payload) to all other parties.
		// This simulates a sender equivocating on broadcast content.
		return m.broadcastEquivocation(env)
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

	// Pre-compute values so we don't repeat work while holding the lock.
	confidential := policy.Confidentiality == ConfidentialityRequired
	peerKeyID, timeNow := fmt.Sprintf("party-%d", env.From), time.Now().Unix()

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
		var secured Envelope
		if !firstSent {
			secured = env.Clone()
			firstSent = true
		} else {
			secured = tampered.Clone()
		}
		secured.Security = SecurityContext{
			Authenticated:      true,
			Confidential:       confidential,
			AuthenticatedParty: env.From,
			ChannelID:          "inmemory-equivocation",
			PeerKeyID:          peerKeyID,
			ReceivedAtUnix:     timeNow,
		}
		select {
		case outbox <- secured:
		default:
			return fmt.Errorf("outbox full for party %d", id)
		}
	}
	return nil
}

// Receive delegates to the inner transport.
func (m *MaliciousTransport) Receive(ctx context.Context) (Envelope, error) {
	return m.inner.Receive(ctx)
}
