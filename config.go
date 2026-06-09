package tss

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// DeliveryPolicy defines the transport requirements for one protocol message kind.
type DeliveryPolicy struct {
	Protocol    ProtocolID
	Round       uint8
	PayloadType PayloadType

	Mode DeliveryMode

	Confidentiality ConfidentialityPolicy

	BroadcastConsistency BroadcastConsistencyPolicy
}

// policyKey is the lookup key for the policy index.
type policyKey struct {
	protocol    ProtocolID
	round       uint8
	payloadType PayloadType
}

// PolicySet is a collection of delivery policies with O(1) lookup by
// (protocol, round, payloadType). Use [NewPolicySet] to construct.
// It must return [ErrUnknownPayloadPolicy] for unregistered payload types.
type PolicySet struct {
	entries []DeliveryPolicy
	index   map[policyKey]int // maps key → index into entries
}

// NewPolicySet builds a PolicySet from a list of delivery policies.
// Duplicate keys are rejected.
func NewPolicySet(policies ...DeliveryPolicy) (PolicySet, error) {
	idx := make(map[policyKey]int, len(policies))
	for i, p := range policies {
		k := policyKey{protocol: p.Protocol, round: p.Round, payloadType: p.PayloadType}
		if _, exists := idx[k]; exists {
			return PolicySet{}, fmt.Errorf("duplicate delivery policy for protocol=%q round=%d payloadType=%q", p.Protocol, p.Round, p.PayloadType)
		}
		idx[k] = i
	}
	return PolicySet{entries: policies, index: idx}, nil
}

// ValidateBroadcastConsistency checks that every broadcast-mode DeliveryPolicy requires
// BroadcastConsistencyRequired. It returns an error listing any broadcast policy that
// does not. Production callers should invoke this once during initialization.
func (ps PolicySet) ValidateBroadcastConsistency() error {
	for _, p := range ps.entries {
		if p.Mode == DeliveryBroadcast && p.BroadcastConsistency != BroadcastConsistencyRequired {
			return fmt.Errorf("broadcast message %q (round %d, protocol %q) must require BroadcastConsistencyRequired", p.PayloadType, p.Round, p.Protocol)
		}
	}
	return nil
}

// MustNewPolicySet is like [NewPolicySet] but panics on duplicate keys or when
// a broadcast-mode policy does not require BroadcastConsistencyRequired.
// It is intended for package-level var initialization where errors are a
// programmer mistake.
func MustNewPolicySet(policies ...DeliveryPolicy) PolicySet {
	ps, err := NewPolicySet(policies...)
	if err != nil {
		panic(err)
	}
	if err := ps.ValidateBroadcastConsistency(); err != nil {
		panic(err)
	}
	return ps
}

// Entries returns the policy entries in registration order.
func (ps PolicySet) Entries() []DeliveryPolicy {
	return ps.entries
}

// Match returns the policy for a given message kind or ErrUnknownPayloadPolicy.
func (ps PolicySet) Match(protocol ProtocolID, round uint8, payloadType PayloadType) (DeliveryPolicy, error) {
	if ps.index == nil {
		return DeliveryPolicy{}, ErrUnknownPayloadPolicy
	}
	k := policyKey{protocol: protocol, round: round, payloadType: payloadType}
	i, ok := ps.index[k]
	if !ok {
		return DeliveryPolicy{}, ErrUnknownPayloadPolicy
	}
	return ps.entries[i], nil
}

// SessionConfig carries the security configuration required to construct a protocol session.
type SessionConfig struct {
	Self        PartyID
	Parties     PartySet
	SessionID   SessionID
	PolicySet   PolicySet
	ReplayCache ReplayCache
}

// GuardConfig carries the guard configuration for protocol sessions that process
// inbound envelopes. It is required for production sessions.
type GuardConfig struct {
	Self      PartyID
	Parties   PartySet
	Protocol  ProtocolID
	SessionID SessionID
	Policies  PolicySet
	Cache     ReplayCache

	// AckVerifier, when non-nil, enables broadcast ack signature verification
	// during guard validation. Production deployments SHOULD set this.
	AckVerifier BroadcastAckVerifier
}

// BuildGuard constructs an EnvelopeGuard from the configuration or returns an error.
// Production deployments must provide a non-nil AckVerifier; test code should use
// [NewTestEnvelopeGuard] instead.
func (c GuardConfig) BuildGuard() (*EnvelopeGuard, error) {
	if c.AckVerifier == nil {
		return nil, ErrMissingAckVerifier
	}
	g, err := NewEnvelopeGuard(c.Self, c.Parties, c.Protocol, c.SessionID, c.Policies, c.Cache)
	if err != nil {
		return nil, err
	}
	g.AckVerifier = c.AckVerifier
	return g, nil
}

// TestGuardConfig returns a GuardConfig suitable for tests using an in-memory replay cache.
// The caller must provide the protocol-specific PolicySet.
func TestGuardConfig(self PartyID, parties PartySet, protocol ProtocolID, sessionID SessionID, policies PolicySet) GuardConfig {
	return GuardConfig{
		Self:      self,
		Parties:   parties,
		Protocol:  protocol,
		SessionID: sessionID,
		Policies:  policies,
		Cache:     NewInMemoryReplayCache(),
	}
}

// ThresholdConfig contains local participant configuration for a protocol run.
type ThresholdConfig struct {
	Threshold    int
	Parties      []PartyID
	Self         PartyID
	SessionID    SessionID
	Rand         io.Reader       `json:"-"`
	Context      context.Context `json:"-"`
	RoundTimeout time.Duration   `json:"-"`
	Log          Logger          `json:"-"`
}

// Ctx returns the configuration context or context.Background when unset.
func (c ThresholdConfig) Ctx() context.Context {
	if c.Context != nil {
		return c.Context
	}
	return context.Background()
}

// Validate checks threshold, party-set, and local-party invariants.
// It uses DefaultLimits as a conservative fallback; callers that know the
// algorithm should prefer ValidateWithLimits with algorithm-specific limits.
func (c ThresholdConfig) Validate() error {
	return c.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks threshold, party-set, and local-party invariants
// against the provided Limits. It enforces hard caps on party count and
// threshold to prevent unbounded resource consumption.
func (c ThresholdConfig) ValidateWithLimits(l Limits) error {
	if err := l.Validate(); err != nil {
		return fmt.Errorf("invalid limits: %w", err)
	}
	if c.Threshold <= 0 {
		return errors.New("threshold must be positive")
	}
	if len(c.Parties) == 0 {
		return errors.New("parties must not be empty")
	}
	if len(c.Parties) > l.MaxParties {
		return fmt.Errorf("too many parties: %d > %d", len(c.Parties), l.MaxParties)
	}
	if c.Threshold > len(c.Parties) {
		return errors.New("threshold exceeds party count")
	}
	if c.Threshold > l.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", c.Threshold, l.MaxThreshold)
	}
	if c.Threshold < l.MinProductionThreshold {
		if !l.AllowOneOfOne || c.Threshold != 1 || len(c.Parties) != 1 {
			return fmt.Errorf("threshold %d is below production minimum %d", c.Threshold, l.MinProductionThreshold)
		}
	}
	seen := make(map[PartyID]struct{}, len(c.Parties))
	hasSelf := false
	for _, id := range c.Parties {
		if id == 0 {
			return errors.New("party id 0 is reserved")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate party id %d", id)
		}
		seen[id] = struct{}{}
		if id == c.Self {
			hasSelf = true
		}
	}
	if !hasSelf {
		return errors.New("self must be in parties")
	}
	return nil
}

// SortedParties returns the configured party set in ascending order.
func (c ThresholdConfig) SortedParties() []PartyID {
	return SortParties(c.Parties)
}

// Reader returns the configured randomness source or crypto/rand.
func (c ThresholdConfig) Reader() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}
