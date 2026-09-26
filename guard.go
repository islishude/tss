package tss

import (
	"errors"
	"fmt"
	"testing"
)

// EnvelopeGuard validates incoming envelopes against protocol, transport, and session policies.
// Every protocol handler must run Validate before processing the envelope.
type EnvelopeGuard struct {
	self      PartyID
	parties   PartySet
	protocol  ProtocolID
	sessionID SessionID

	policies     PolicySet
	policyDigest [32]byte
	replayCache  ReplayCache

	// AckVerifier verifies individual broadcast ack signatures during broadcast
	// certificate validation. Production guards must set a non-nil verifier;
	// [NewTestEnvelopeGuard] provides a no-op verifier for tests that do not
	// exercise broadcast consistency.
	ackVerifier BroadcastAckVerifier
	// EnvelopeVerifier verifies portable sender signatures required by policy.
	envelopeVerifier EnvelopeSignatureVerifier
	testOnly         bool
}

// NewEnvelopeGuard constructs a guard with the required security configuration.
// It returns an error if parties is empty, Self is not in Parties, or if the SessionID is invalid.
func NewEnvelopeGuard(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet, cache ReplayCache) (*EnvelopeGuard, error) {
	return newEnvelopeGuard(self, parties, protocol, sessionID, policies, cache, nil, nil, false)
}

func newEnvelopeGuard(
	self PartyID,
	parties PartySet,
	protocol ProtocolID,
	sessionID SessionID,
	policies PolicySet,
	cache ReplayCache,
	ackVerifier BroadcastAckVerifier,
	envelopeVerifier EnvelopeSignatureVerifier,
	testOnly bool,
) (*EnvelopeGuard, error) {
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
	if !policies.valid() {
		return nil, errors.New("guard policy set must not be empty")
	}
	if policies.testOnly && !testOnly {
		return nil, errors.New("test-only policy set requires a test-only guard")
	}
	if !testOnly {
		if err := policies.ValidateBroadcastConsistency(); err != nil {
			return nil, err
		}
	}
	return &EnvelopeGuard{
		self:             self,
		parties:          parties.Clone(),
		protocol:         protocol,
		sessionID:        sessionID,
		policies:         policies,
		policyDigest:     policies.Digest(),
		replayCache:      cache,
		ackVerifier:      ackVerifier,
		envelopeVerifier: envelopeVerifier,
		testOnly:         testOnly,
	}, nil
}

// NewTestEnvelopeGuard constructs a guard suitable for tests. It uses an in-memory
// replay cache and a no-op ack verifier. This function MUST NOT be used in production
// code — production callers must use [GuardConfig.BuildGuard] with a real verifier.
//
// It panics when not running under "go test" to prevent accidental production use.
func NewTestEnvelopeGuard(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet) *EnvelopeGuard {
	return NewTestEnvelopeGuardWithCache(self, parties, protocol, sessionID, policies, NewInMemoryReplayCache())
}

// NewTestEnvelopeGuardWithCache is [NewTestEnvelopeGuard] with an explicit
// replay cache for bounded-cache and failure-injection tests.
func NewTestEnvelopeGuardWithCache(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet, cache ReplayCache) *EnvelopeGuard {
	if !testing.Testing() {
		panic("NewTestEnvelopeGuardWithCache must only be called from tests")
	}
	g, err := newEnvelopeGuard(
		self,
		parties,
		protocol,
		sessionID,
		policies,
		cache,
		&noopAckVerifier{},
		noopEnvelopeSignatureVerifier{},
		true,
	)
	if err != nil {
		panic(fmt.Sprintf("NewTestEnvelopeGuardWithCache: %v", err))
	}
	return g
}

// Self returns the local party bound to the guard.
func (g *EnvelopeGuard) Self() PartyID {
	if g == nil {
		return BroadcastPartyId
	}
	return g.self
}

// Parties returns a caller-owned copy of the guard's construction-time party universe.
func (g *EnvelopeGuard) Parties() PartySet {
	if g == nil {
		return nil
	}
	return g.parties.Clone()
}

// Protocol returns the protocol bound to the guard.
func (g *EnvelopeGuard) Protocol() ProtocolID {
	if g == nil {
		return ""
	}
	return g.protocol
}

// SessionID returns the session identifier bound to the guard.
func (g *EnvelopeGuard) SessionID() SessionID {
	if g == nil {
		return SessionID{}
	}
	return g.sessionID
}

// Policies returns the guard's immutable policy set.
func (g *EnvelopeGuard) Policies() PolicySet {
	if g == nil {
		return PolicySet{}
	}
	return g.policies
}

// PolicyDigest returns the canonical delivery-policy digest bound at construction.
func (g *EnvelopeGuard) PolicyDigest() [32]byte {
	if g == nil {
		return [32]byte{}
	}
	return g.policyDigest
}

// ReplayCache returns the guard's replay cache authority.
func (g *EnvelopeGuard) ReplayCache() ReplayCache {
	if g == nil {
		return nil
	}
	return g.replayCache
}

// AckVerifier returns the guard's broadcast acknowledgement verifier.
func (g *EnvelopeGuard) AckVerifier() BroadcastAckVerifier {
	if g == nil {
		return nil
	}
	return g.ackVerifier
}

// EnvelopeVerifier returns the guard's portable sender-signature verifier.
func (g *EnvelopeGuard) EnvelopeVerifier() EnvelopeSignatureVerifier {
	if g == nil {
		return nil
	}
	return g.envelopeVerifier
}

// RequiresSenderSignatures reports whether any delivery policy configured on
// the guard requires canonical sender signatures.
func (g *EnvelopeGuard) RequiresSenderSignatures() bool {
	return g != nil && g.policies.requiresSenderSignature()
}

// noopAckVerifier is a BroadcastAckVerifier that accepts any signature.
// It is used exclusively by [NewTestEnvelopeGuard] for tests that do not
// exercise broadcast ack signature verification.
type noopAckVerifier struct{}

// VerifyAck implements BroadcastAckVerifier by accepting any signature.
func (noopAckVerifier) VerifyAck(party PartyID, digest [32]byte, signature []byte) error {
	return nil
}

type noopEnvelopeSignatureVerifier struct{}

// VerifyEnvelopeSignature accepts signatures in test-only envelope guards.
func (noopEnvelopeSignatureVerifier) VerifyEnvelopeSignature(PartyID, [32]byte, []byte) error {
	return nil
}

// Validate executes the full security validation sequence on an incoming envelope
// against the guard's configured party set. It returns nil only when the envelope
// passes all checks.
func (g *EnvelopeGuard) Validate(env InboundEnvelope) error {
	if g == nil {
		return ErrMissingEnvelopeGuard
	}
	return g.ValidateWithParties(env, g.parties)
}

// ValidateWithParties is like Validate but validates sender membership and
// broadcast certificates against the provided party set instead of the guard's
// configured set. This is used by sessions (e.g. reshare) that accept messages
// from different participant subsets depending on payload type.
func (g *EnvelopeGuard) ValidateWithParties(env InboundEnvelope, parties PartySet) error {
	return g.validateWithParties(env, parties, true)
}

// ValidateWithoutReplay performs all transport, identity, delivery-policy,
// confidentiality, signature, and broadcast-certificate checks without
// reserving a replay slot. It is intended only for protocol messages that are
// explicitly rejected as too early and may be retried after readiness changes.
func (g *EnvelopeGuard) ValidateWithoutReplay(env InboundEnvelope, parties PartySet) error {
	return g.validateWithParties(env, parties, false)
}

func (g *EnvelopeGuard) validateWithParties(env InboundEnvelope, parties PartySet, commitReplay bool) error {
	base := env.Envelope()
	info := env.ReceiveInfo()

	// 1. Protocol match.
	if base.Protocol != g.protocol {
		s := fmt.Sprintf("unexpected protocol %q", base.Protocol)
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, errors.New(s))
	}

	// 2. Session ID match.
	if base.SessionID != g.sessionID {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, errors.New("session mismatch"))
	}

	// 3. Sender membership in the provided party set.
	if !parties.Contains(base.From) {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("sender %d is not a participant", base.From))
	}
	if base.From == g.self {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, ErrSelfSender)
	}

	// 4. Transport authentication.
	if info.Peer == BroadcastPartyId {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, ErrUnauthenticatedTransport)
	}

	// 5. Transport identity must match envelope sender.
	if info.Peer != base.From {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: authenticated %d, envelope from %d", ErrSenderIdentityMismatch, info.Peer, base.From))
	}

	// 6. Channel protection must be set.
	if info.Protection == ChannelProtectionUnknown {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, ErrMissingChannelProtection)
	}
	if !validChannelProtection(info.Protection) {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %d", ErrInvalidChannelProtection, info.Protection))
	}

	// 7. Recipient check for direct messages.
	if base.To != BroadcastPartyId && base.To != g.self {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: expected %d, got %d", ErrWrongRecipient, g.self, base.To))
	}

	// 9. Policy lookup.
	policy, err := g.policies.Match(base.Protocol, base.Round, base.PayloadType)
	if err != nil {
		return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, err)
	}
	if policy.RequireSenderSignature {
		if g.envelopeVerifier == nil {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, ErrMissingEnvelopeSignatureVerifier)
		}
		if err := VerifyEnvelopeSignature(base, g.envelopeVerifier); err != nil {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, err)
		}
	}

	if err := validateInboundDeliveryPolicy(base, info, policy); err != nil {
		return err
	}

	// 12. Broadcast consistency enforcement against the provided party set.
	if policy.BroadcastConsistency == BroadcastConsistencyRequired {
		cert := env.BroadcastCertificate()
		if cert == nil {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %s", ErrMissingBroadcastCertificate, base.PayloadType))
		}
		if err := cert.VerifyFull(base, parties, g.ackVerifier); err != nil {
			return NewProtocolError(ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("%w: %w", ErrInvalidBroadcastCertificate, err))
		}
	}

	if !commitReplay {
		return nil
	}

	// 13. Replay and equivocation detection.
	// Duplicate messages (same slot, same payload hash) return
	// [ErrDuplicateMessage] so handlers can drop them before parsing
	// payloads. Equivocation (same slot, different payload hash) is
	// always a verification error because it indicates a malicious or
	// faulty sender.
	slot := SlotKeyFromEnvelope(base)
	payloadHash := PayloadHashFromEnvelope(base)
	if err := g.replayCache.CheckAndStore(slot, payloadHash); err != nil {
		if errors.Is(err, ErrDuplicateMessage) {
			return ErrDuplicateMessage
		}
		return NewProtocolError(ErrCodeVerification, base.Round, base.From, err)
	}

	return nil
}

// ValidateForRound validates an incoming envelope against the sender set allowed
// by the current protocol round or payload. The guard's configured Parties field
// remains the construction-time party universe; allowedSenders is the
// lifecycle-specific sender set for this message.
func (g *EnvelopeGuard) ValidateForRound(env InboundEnvelope, allowedSenders PartySet) error {
	return g.ValidateWithParties(env, allowedSenders)
}

// RequireEnvelopeGuard verifies that guard is bound to the expected protocol
// session and has the fixed validation dependencies required by inbound
// handlers. It does not validate the guard's party set; protocol handlers pass
// the per-message allowed sender set to [ValidateInbound].
func RequireEnvelopeGuard(guard *EnvelopeGuard, expectedProtocol ProtocolID, expectedSession SessionID, self PartyID, expectedPolicies PolicySet) error {
	if err := requireEnvelopeGuardIdentity(guard, expectedProtocol, expectedSession, self); err != nil {
		return err
	}
	if !expectedPolicies.valid() || (expectedPolicies.testOnly && (!guard.testOnly || !testing.Testing())) {
		return errors.New("expected production policy set is invalid")
	}
	if guard.policyDigest != expectedPolicies.Digest() && (!guard.testOnly || !testing.Testing()) {
		return errors.New("guard delivery policy does not match the protocol canonical policy")
	}
	return nil
}

func requireEnvelopeGuardIdentity(guard *EnvelopeGuard, expectedProtocol ProtocolID, expectedSession SessionID, self PartyID) error {
	if guard == nil {
		return ErrMissingEnvelopeGuard
	}
	if guard.protocol != expectedProtocol {
		return fmt.Errorf("guard protocol %q does not match expected %q", guard.protocol, expectedProtocol)
	}
	if guard.sessionID != expectedSession {
		return fmt.Errorf("guard session %x does not match expected %x", guard.sessionID[:], expectedSession[:])
	}
	if guard.self != self {
		return fmt.Errorf("guard self %d does not match expected %d", guard.self, self)
	}
	if !guard.policies.valid() {
		return errors.New("guard policy set must not be empty")
	}
	if guard.replayCache == nil {
		return ErrMissingReplayCache
	}
	if guard.ackVerifier == nil {
		return ErrMissingAckVerifier
	}
	if guard.policies.requiresSenderSignature() && guard.envelopeVerifier == nil {
		return ErrMissingEnvelopeSignatureVerifier
	}
	return nil
}

// ValidateInbound validates an incoming envelope through the provided guard.
// The guard must be non-nil — a nil guard returns [ErrMissingEnvelopeGuard].
// This ensures transport authentication, confidentiality enforcement, broadcast
// consistency, and replay detection are applied uniformly in all code paths.
//
// The allowedSenders parameter specifies which participants are accepted as
// senders for this message. The guard's configured [EnvelopeGuard.Parties] field
// is the construction-time party universe; callers must supply the appropriate
// allowed sender set per round or per payload type. For sessions where the
// trusted party universe changes between rounds (e.g. reshare with old and new
// party subsets), this design avoids coupling guard construction to
// per-message validation.
func ValidateInbound(guard *EnvelopeGuard, env InboundEnvelope, expectedProtocol ProtocolID, expectedSession SessionID, allowedSenders PartySet, self PartyID) error {
	if err := requireEnvelopeGuardIdentity(guard, expectedProtocol, expectedSession, self); err != nil {
		return err
	}
	if len(allowedSenders) == 0 {
		return errors.New("allowed senders must not be empty")
	}
	return guard.ValidateForRound(env, allowedSenders)
}

// ValidateInboundWithoutReplay validates a retryable early message without
// mutating the guard's replay cache. Once the protocol becomes ready, callers
// must pass the message through [ValidateInbound] before processing it.
func ValidateInboundWithoutReplay(guard *EnvelopeGuard, env InboundEnvelope, expectedProtocol ProtocolID, expectedSession SessionID, allowedSenders PartySet, self PartyID) error {
	if err := requireEnvelopeGuardIdentity(guard, expectedProtocol, expectedSession, self); err != nil {
		return err
	}
	if len(allowedSenders) == 0 {
		return errors.New("allowed senders must not be empty")
	}
	return guard.ValidateWithoutReplay(env, allowedSenders)
}

func validateInboundDeliveryPolicy(base Envelope, info ReceiveInfo, policy DeliveryPolicy) error {
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

	return nil
}
