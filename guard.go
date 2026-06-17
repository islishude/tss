package tss

import (
	"errors"
	"fmt"
	"testing"
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
// It returns an error if parties is empty, Self is not in Parties, or if the SessionID is invalid.
func NewEnvelopeGuard(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet, cache ReplayCache) (*EnvelopeGuard, error) {
	if len(parties) == 0 {
		return nil, errors.New("guard parties must not be empty")
	}
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
//
// It panics when not running under "go test" to prevent accidental production use.
func NewTestEnvelopeGuard(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet) *EnvelopeGuard {
	if !testing.Testing() {
		panic("NewTestEnvelopeGuard must only be called from tests")
	}
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
func (g *EnvelopeGuard) Validate(env InboundEnvelope) error {
	return g.ValidateWithParties(env, g.Parties)
}

// ValidateWithParties is like Validate but validates sender membership and
// broadcast certificates against the provided party set instead of the guard's
// configured set. This is used by sessions (e.g. reshare) that accept messages
// from different participant subsets depending on payload type.
func (g *EnvelopeGuard) ValidateWithParties(env InboundEnvelope, parties PartySet) error {
	base := env.Envelope()
	info := env.ReceiveInfo()

	// 1. Protocol match.
	if base.Protocol != g.Protocol {
		s := fmt.Sprintf("unexpected protocol %q", base.Protocol)
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, errors.New(s))
	}

	// 2. Session ID match.
	if base.SessionID != g.SessionID {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, errors.New("session mismatch"))
	}

	// 3. Version check.
	if base.Version != Version {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected version %d", base.Version))
	}

	// 4. Sender membership in the provided party set.
	if !parties.Contains(base.From) {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("sender %d is not a participant", base.From))
	}

	// 5. Transport authentication.
	if info.Peer == BroadcastPartyId {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, ErrUnauthenticatedTransport)
	}

	// 6. Transport identity must match envelope sender.
	if info.Peer != base.From {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: authenticated %d, envelope from %d", ErrSenderIdentityMismatch, info.Peer, base.From))
	}

	// 7. Channel protection must be set.
	if info.Protection == ChannelProtectionUnknown {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, ErrMissingChannelProtection)
	}

	// 8. Recipient check for direct messages.
	if base.To != BroadcastPartyId && base.To != g.Self {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: expected %d, got %d", ErrWrongRecipient, g.Self, base.To))
	}

	// 9. Policy lookup.
	policy, err := g.Policies.Match(base.Protocol, base.Round, base.PayloadType)
	if err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, err)
	}

	// 10. Delivery mode enforcement.
	switch policy.Mode {
	case DeliveryDirect:
		if base.To == BroadcastPartyId {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %s", ErrExpectedDirectMessage, base.PayloadType))
		}
	case DeliveryBroadcast:
		if base.To != BroadcastPartyId {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, base.PayloadType))
		}
	default:
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unknown delivery mode %d: %s", policy.Mode, base.PayloadType))
	}

	// 11. Confidentiality enforcement.
	switch policy.Confidentiality {
	case ConfidentialityRequired:
		if info.Protection != ChannelConfidential {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %s", ErrMissingConfidentiality, base.PayloadType))
		}
	case ConfidentialityForbidden:
		if info.Protection == ChannelConfidential {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %s", ErrUnexpectedConfidentiality, base.PayloadType))
		}
	case ConfidentialityOptional:
		// nothing to enforce — either plaintext or confidential is acceptable
	default:
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unknown confidentiality policy %d: %s", policy.Confidentiality, base.PayloadType))
	}

	// 12. Broadcast consistency enforcement against the provided party set.
	if policy.BroadcastConsistency == BroadcastConsistencyRequired {
		cert := env.BroadcastCertificate()
		if cert == nil {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %s", ErrMissingBroadcastCertificate, base.PayloadType))
		}
		if err := cert.VerifyFull(base, parties, g.AckVerifier); err != nil {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %w", ErrInvalidBroadcastCertificate, err))
		}
	}

	// 13. Replay and equivocation detection.
	// Duplicate messages (same slot, same payload hash) return
	// [ErrDuplicateMessage] so handlers can drop them before parsing
	// payloads. Equivocation (same slot, different payload hash) is
	// always a verification error because it indicates a malicious or
	// faulty sender.
	slot := SlotKeyFromEnvelope(base)
	payloadHash := PayloadHashFromEnvelope(base)
	if err := g.ReplayCache.CheckAndStore(slot, payloadHash); err != nil {
		if errors.Is(err, ErrDuplicateMessage) {
			return ErrDuplicateMessage
		}
		return NewProtocolError(ErrCodeVerification, base.Round, base.From, err)
	}

	return nil
}

// RequireEnvelopeGuard verifies that guard is bound to the expected protocol
// session and has the fixed validation dependencies required by inbound
// handlers. It does not validate the guard's party set; protocol handlers pass
// the per-message allowed sender set to [ValidateInbound].
func RequireEnvelopeGuard(guard *EnvelopeGuard, expectedProtocol ProtocolID, expectedSession SessionID, self PartyID) error {
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
	if len(guard.Policies.entries) == 0 || guard.Policies.index == nil {
		return errors.New("guard policy set must not be empty")
	}
	if guard.ReplayCache == nil {
		return ErrMissingReplayCache
	}
	return nil
}

// ValidateInbound validates an incoming envelope through the provided guard.
// The guard must be non-nil — a nil guard returns [ErrMissingEnvelopeGuard].
// This ensures transport authentication, confidentiality enforcement, broadcast
// consistency, and replay detection are applied uniformly in all code paths.
//
// The parties parameter specifies which participants are accepted as senders
// for this message. The guard's configured [EnvelopeGuard.Parties] field is NOT
// used to restrict the sender set — callers must supply the appropriate party
// set per round or per payload type. For sessions where the trusted party
// universe changes between rounds (e.g. reshare with old and new party
// subsets), this design avoids coupling the guard's construction-time party set
// to per-message validation.
func ValidateInbound(guard *EnvelopeGuard, env InboundEnvelope, expectedProtocol ProtocolID, expectedSession SessionID, parties PartySet, self PartyID) error {
	if err := RequireEnvelopeGuard(guard, expectedProtocol, expectedSession, self); err != nil {
		return err
	}
	if len(parties) == 0 {
		return errors.New("parties must not be empty")
	}
	return guard.ValidateWithParties(env, parties)
}
