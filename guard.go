package tss

import (
	"errors"
	"fmt"
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

	// AckVerifier, when non-nil, verifies individual broadcast ack signatures
	// during broadcast certificate validation. When nil, only structural
	// certificate checks are performed (backward-compatible behavior).
	// Production deployments SHOULD set this to ensure end-to-end broadcast
	// integrity.
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
		return fmt.Errorf("%w", ErrUnauthenticatedTransport)
	}

	// 7. Transport identity must be set.
	if env.Security.AuthenticatedParty == 0 {
		return fmt.Errorf("%w: authenticated party is zero (unset)", ErrUnauthenticatedTransport)
	}
	// 8. Transport identity must match envelope sender.
	if env.Security.AuthenticatedParty != env.From {
		return fmt.Errorf("%w: authenticated %d, envelope from %d", ErrSenderIdentityMismatch, env.Security.AuthenticatedParty, env.From)
	}

	// 9. Recipient check for direct messages.
	if env.To != 0 && env.To != g.Self {
		return fmt.Errorf("%w: expected %d, got %d", ErrWrongRecipient, g.Self, env.To)
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
			return fmt.Errorf("%w: %s", ErrExpectedDirectMessage, env.PayloadType)
		}
	case DeliveryBroadcast:
		if env.To != 0 {
			return fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, env.PayloadType)
		}
	}

	// 12. Confidentiality enforcement.
	switch policy.Confidentiality {
	case ConfidentialityRequired:
		if !env.Security.Confidential {
			return fmt.Errorf("%w: %s", ErrMissingConfidentiality, env.PayloadType)
		}
	case ConfidentialityForbidden:
		if env.Security.Confidential {
			return fmt.Errorf("%w: %s", ErrUnexpectedConfidentiality, env.PayloadType)
		}
	}

	// 13. Broadcast consistency enforcement against the provided party set.
	if policy.BroadcastConsistency == BroadcastConsistencyRequired {
		if env.Broadcast == nil {
			return fmt.Errorf("%w: %s", ErrMissingBroadcastCertificate, env.PayloadType)
		}
		if err := env.Broadcast.Verify(env, parties); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidBroadcastCertificate, err)
		}
		// Verify individual ack signatures when a verifier is configured.
		// This closes the gap where a transport adapter attaches a structurally
		// valid certificate without verifying the underlying signatures.
		if g.AckVerifier != nil {
			for _, ack := range env.Broadcast.Acks {
				if err := VerifyBroadcastAck(env, ack, g.AckVerifier); err != nil {
					return fmt.Errorf("%w: party %d: %w", ErrInvalidBroadcastCertificate, ack.Party, err)
				}
			}
		}
	}

	// 14. Replay detection.
	key := ReplayKeyFromEnvelope(env)
	if !g.ReplayCache.MarkIfNew(key) {
		return fmt.Errorf("%w: protocol=%s session=%s round=%d from=%d", ErrReplay, env.Protocol, env.SessionID, env.Round, env.From)
	}

	return nil
}

// ValidateInbound validates an incoming envelope through the provided guard.
// Production code must always provide a non-nil guard — this ensures transport
// authentication, confidentiality enforcement, broadcast consistency, and replay
// detection are applied uniformly.
//
// When guard is nil and the transport is unauthenticated, a limited set of
// structural checks is applied as a test-only fallback. This path MUST NOT be
// relied upon in production; it exists solely for Tier 0 unit tests that
// exercise protocol logic without a full transport simulation.
func ValidateInbound(guard *EnvelopeGuard, env Envelope, expectedProtocol ProtocolID, expectedSession SessionID, parties PartySet, self PartyID, policies PolicySet) error {
	if guard != nil {
		return guard.Validate(env)
	}
	// Test-only fallback: structural checks without transport security.
	// Production transports must always authenticate — an unauthenticated
	// envelope in production is a configuration error caught by the guard.
	if env.Security.Authenticated {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From,
			errors.New("envelope guard is required for authenticated transport; call SetGuard before processing messages"))
	}
	if err := ValidateEnvelope(env, expectedProtocol, expectedSession, parties); err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := ValidateEnvelopePolicy(env, self, policies); err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	return nil
}

// ValidateInboundWithParties is like [ValidateInbound] but validates sender
// membership and broadcast certificates against the provided party set instead
// of the guard's configured set. This is used by sessions (e.g. reshare) that
// accept messages from different participant subsets depending on payload type.
func ValidateInboundWithParties(guard *EnvelopeGuard, env Envelope, expectedProtocol ProtocolID, expectedSession SessionID, parties PartySet, self PartyID, policies PolicySet) error {
	if guard != nil {
		return guard.ValidateWithParties(env, parties)
	}
	// Test-only fallback: structural checks without transport security.
	if env.Security.Authenticated {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From,
			errors.New("envelope guard is required for authenticated transport; call SetGuard before processing messages"))
	}
	if err := ValidateEnvelope(env, expectedProtocol, expectedSession, parties); err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := ValidateEnvelopePolicy(env, self, policies); err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	return nil
}

// ReplayKeyFromEnvelope constructs a replay key from the envelope's identifying fields.
func ReplayKeyFromEnvelope(env Envelope) ReplayKey {
	return ReplayKey{
		Protocol:       env.Protocol,
		SessionID:      env.SessionID,
		Round:          env.Round,
		From:           env.From,
		To:             env.To,
		PayloadType:    env.PayloadType,
		TranscriptHash: env.TranscriptHash,
	}
}
