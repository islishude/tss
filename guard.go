package tss

import (
	"errors"
	"fmt"
	"slices"
)

// EnvelopeGuard validates incoming envelopes against protocol, transport, and session policies.
// Every protocol handler must run Validate before processing the envelope.
type EnvelopeGuard struct {
	Self      PartyID
	Parties   PartySet
	Protocol  ProtocolID
	SessionID SessionID

	Policies    PolicySet
	ReplayCache ReplayCache

	// AckVerifier verifies individual broadcast ack signatures during broadcast
	// certificate validation. Production guards must set a non-nil verifier;
	// [NewTestEnvelopeGuard] provides a no-op verifier for tests that do not
	// exercise broadcast consistency.
	AckVerifier BroadcastAckVerifier
}

// NewEnvelopeGuard constructs a guard with the required security configuration.
// It returns an error if Self is not in Parties or if the SessionID is invalid.
func NewEnvelopeGuard(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet, cache ReplayCache) (*EnvelopeGuard, error) {
	if !parties.Contains(self) {
		return nil, errors.New("guard self is not in parties")
	}
	if protocol == "" {
		return nil, errors.New("guard protocol is empty")
	}
	if !sessionID.Valid() {
		return nil, ErrInvalidSessionID
	}
	if cache == nil {
		return nil, ErrMissingReplayCache
	}
	return &EnvelopeGuard{
		Self:        self,
		Parties:     parties.Clone(),
		Protocol:    protocol,
		SessionID:   sessionID,
		Policies:    policies,
		ReplayCache: cache,
	}, nil
}

// NewTestEnvelopeGuard constructs a guard suitable for tests. It uses an in-memory
// replay cache and a no-op ack verifier. This function MUST NOT be used in production
// code — production callers must use [GuardConfig.BuildGuard] with a real verifier.
func NewTestEnvelopeGuard(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet) *EnvelopeGuard {
	g, err := NewEnvelopeGuard(self, parties, protocol, sessionID, policies, NewInMemoryReplayCache())
	if err != nil {
		panic(fmt.Sprintf("NewTestEnvelopeGuard: %v", err))
	}
	g.AckVerifier = &noopAckVerifier{}
	return g
}

// noopAckVerifier is a BroadcastAckVerifier that accepts any signature.
// It is used exclusively by [NewTestEnvelopeGuard] for tests that do not
// exercise broadcast ack signature verification.
type noopAckVerifier struct{}

// VerifyAck implements BroadcastAckVerifier by accepting any signature.
func (noopAckVerifier) VerifyAck(party PartyID, digest [32]byte, signature []byte) error {
	return nil
}

// Validate executes the full security validation sequence on an incoming envelope
// against the guard's configured party set. It returns nil only when the envelope
// passes all checks.
func (g *EnvelopeGuard) Validate(env Envelope) error {
	return g.ValidateWithParties(env, g.Parties)
}

// ValidateWithParties is like Validate but validates sender membership and
// broadcast certificates against the provided party set instead of the guard's
// configured set. This is used by sessions (e.g. reshare) that accept messages
// from different participant subsets depending on payload type.
func (g *EnvelopeGuard) ValidateWithParties(env Envelope, parties PartySet) error {
	// 1. Protocol match.
	if env.Protocol != g.Protocol {
		s := fmt.Sprintf("unexpected protocol %q", env.Protocol)
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, errors.New(s))
	}

	// 2. Session ID match.
	if env.SessionID != g.SessionID {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, errors.New("session mismatch"))
	}

	// 3. Version check.
	if env.Version != Version {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected version %d", env.Version))
	}

	// 4. Transcript hash integrity.
	if err := VerifyTranscriptHash(env); err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, err)
	}

	// 5. Sender membership in the provided party set.
	if !parties.Contains(env.From) {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("sender %d is not a participant", env.From))
	}

	// 6. Transport authentication.
	if !env.Security.Authenticated {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, ErrUnauthenticatedTransport)
	}

	// 7. Transport identity must be set.
	if env.Security.AuthenticatedParty == 0 {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: authenticated party is zero (unset)", ErrUnauthenticatedTransport))
	}
	// 8. Transport identity must match envelope sender.
	if env.Security.AuthenticatedParty != env.From {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: authenticated %d, envelope from %d", ErrSenderIdentityMismatch, env.Security.AuthenticatedParty, env.From))
	}

	// 9. Recipient check for direct messages.
	if env.To != 0 && env.To != g.Self {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: expected %d, got %d", ErrWrongRecipient, g.Self, env.To))
	}

	// 10. Policy lookup.
	policy, err := g.Policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, err)
	}

	// 11. Delivery mode enforcement.
	switch policy.Mode {
	case DeliveryDirect:
		if env.To == 0 {
			return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: %s", ErrExpectedDirectMessage, env.PayloadType))
		}
	case DeliveryBroadcast:
		if env.To != 0 {
			return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, env.PayloadType))
		}
	}

	// 12. Confidentiality enforcement.
	switch policy.Confidentiality {
	case ConfidentialityRequired:
		if !env.Security.Confidential {
			return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: %s", ErrMissingConfidentiality, env.PayloadType))
		}
	case ConfidentialityForbidden:
		if env.Security.Confidential {
			return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: %s", ErrUnexpectedConfidentiality, env.PayloadType))
		}
	}

	// 13. Broadcast consistency enforcement against the provided party set.
	if policy.BroadcastConsistency == BroadcastConsistencyRequired {
		if env.Broadcast == nil {
			return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: %s", ErrMissingBroadcastCertificate, env.PayloadType))
		}
		if err := env.Broadcast.VerifyFull(env, parties, g.AckVerifier); err != nil {
			return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("%w: %w", ErrInvalidBroadcastCertificate, err))
		}
	}

	// 14. Replay and equivocation detection.
	// Duplicate messages (same slot, same transcript) are silently dropped;
	// handlers have their own per-round duplicate detection and may ignore
	// harmless duplicates (e.g., commitment re-delivery).
	// Equivocation (same slot, different transcript) is always an error
	// because it indicates a malicious or faulty sender.
	slot := SlotKeyFromEnvelope(env)
	payloadHash := PayloadHashFromEnvelope(env)
	if err := g.ReplayCache.CheckAndStore(slot, payloadHash); err != nil {
		if errors.Is(err, ErrDuplicateMessage) {
			return nil // silently drop duplicate
		}
		return NewProtocolError(ErrCodeVerification, env.Round, env.From, err)
	}

	return nil
}

// ValidateInbound validates an incoming envelope through the provided guard.
// The guard must be non-nil — a nil guard returns [ErrMissingEnvelopeGuard].
// This ensures transport authentication, confidentiality enforcement, broadcast
// consistency, and replay detection are applied uniformly in all code paths.
func ValidateInbound(guard *EnvelopeGuard, env Envelope, expectedProtocol ProtocolID, expectedSession SessionID, parties PartySet, self PartyID, policies PolicySet) error {
	if guard == nil {
		return ErrMissingEnvelopeGuard
	}
	if guard.Protocol != expectedProtocol {
		return fmt.Errorf("guard protocol %q does not match expected %q", guard.Protocol, expectedProtocol)
	}
	if guard.SessionID != expectedSession {
		return fmt.Errorf("guard session %x does not match expected %x", guard.SessionID[:], expectedSession[:])
	}
	if !slices.Equal(guard.Parties, parties) {
		return fmt.Errorf("guard parties %v do not match expected %v", guard.Parties, parties)
	}
	if guard.Self != self {
		return fmt.Errorf("guard self %d does not match expected %d", guard.Self, self)
	}
	return guard.Validate(env)
}

// ValidateInboundWithParties is like [ValidateInbound] but validates sender
// membership and broadcast certificates against the provided party set instead
// of the guard's configured set. This is used by sessions (e.g. reshare) that
// accept messages from different participant subsets depending on payload type.
func ValidateInboundWithParties(guard *EnvelopeGuard, env Envelope, expectedProtocol ProtocolID, expectedSession SessionID, parties PartySet, self PartyID, policies PolicySet) error {
	if guard == nil {
		return ErrMissingEnvelopeGuard
	}
	if guard.Protocol != expectedProtocol {
		return fmt.Errorf("guard protocol %q does not match expected %q", guard.Protocol, expectedProtocol)
	}
	if guard.SessionID != expectedSession {
		return fmt.Errorf("guard session %x does not match expected %x", guard.SessionID[:], expectedSession[:])
	}
	if guard.Self != self {
		return fmt.Errorf("guard self %d does not match expected %d", guard.Self, self)
	}
	return guard.ValidateWithParties(env, parties)
}
