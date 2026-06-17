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
// It clones the input slice so callers cannot mutate the policy entries
// after construction. Duplicate keys are rejected.
func NewPolicySet(policies ...DeliveryPolicy) (PolicySet, error) {
	cloned := append([]DeliveryPolicy(nil), policies...)
	idx := make(map[policyKey]int, len(cloned))
	for i, p := range cloned {
		k := policyKey{protocol: p.Protocol, round: p.Round, payloadType: p.PayloadType}
		if _, exists := idx[k]; exists {
			return PolicySet{}, fmt.Errorf("duplicate delivery policy for protocol=%q round=%d payloadType=%q", p.Protocol, p.Round, p.PayloadType)
		}
		idx[k] = i
	}
	return PolicySet{entries: cloned, index: idx}, nil
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

// Entries returns a copy of the policy entries in registration order.
func (ps PolicySet) Entries() []DeliveryPolicy {
	return append([]DeliveryPolicy(nil), ps.entries...)
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
	Parties      PartySet
	Self         PartyID
	SessionID    SessionID
	Rand         io.Reader       `json:"-"`
	Context      context.Context `json:"-"`
	RoundTimeout time.Duration   `json:"-"`
	Log          Logger          `json:"-"`
}

// LocalConfig contains per-process runtime configuration for one protocol
// participant. Consensus parameters such as threshold, party set, session ID,
// signer set, derivation context, and HD enablement belong in protocol-specific
// plan objects, not in LocalConfig.
type LocalConfig struct {
	Self         PartyID
	Rand         io.Reader       `json:"-"`
	Context      context.Context `json:"-"`
	RoundTimeout time.Duration   `json:"-"`
	Log          Logger          `json:"-"`
}

// Ctx returns the local configuration context or context.Background when unset.
func (c LocalConfig) Ctx() context.Context {
	if c.Context != nil {
		return c.Context
	}
	return context.Background()
}

// Reader returns the configured randomness source or crypto/rand.
func (c LocalConfig) Reader() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

// Ctx returns the configuration context or context.Background when unset.
func (c ThresholdConfig) Ctx() context.Context {
	if c.Context != nil {
		return c.Context
	}
	return context.Background()
}

// Validate checks threshold, party-set, and local-party invariants using
// conservative default limits. Callers that know the algorithm should prefer
// ValidateWithLimits with algorithm-specific limits.
func (c ThresholdConfig) Validate() error {
	return c.ValidateWithLimits(ThresholdLimits{
		MaxParties:              DefaultMaxParties,
		MaxThreshold:            DefaultMaxThreshold,
		MaxSigners:              DefaultMaxSigners,
		MinProductionThreshold:  2,
		AllowOneOfOne:           false,
		AllowOversizedSignerSet: false,
	})
}

// ValidateWithLimits checks threshold, party-set, and local-party invariants
// against the provided ThresholdLimits. It enforces hard caps on party count and
// threshold to prevent unbounded resource consumption.
func (c ThresholdConfig) ValidateWithLimits(l ThresholdLimits) error {
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
	if err := l.ValidateThreshold(c.Threshold, len(c.Parties)); err != nil {
		return err
	}
	seen := make(map[PartyID]struct{}, len(c.Parties))
	hasSelf := false
	for _, id := range c.Parties {
		if id == BroadcastPartyId {
			return errors.New("party id zero is reserved")
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
func (c ThresholdConfig) SortedParties() PartySet {
	return c.Parties.Sorted()
}

// Reader returns the configured randomness source or crypto/rand.
func (c ThresholdConfig) Reader() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}
