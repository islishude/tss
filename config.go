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

// PolicySet is a collection of delivery policies keyed by (protocol, round, payloadType).
// It must return ErrUnknownPayloadPolicy for unregistered payload types.
type PolicySet []DeliveryPolicy

// Match returns the policy for a given message kind or ErrUnknownPayloadPolicy.
func (ps PolicySet) Match(protocol ProtocolID, round uint8, payloadType PayloadType) (DeliveryPolicy, error) {
	for _, p := range ps {
		if p.Protocol == protocol && p.Round == round && p.PayloadType == payloadType {
			return p, nil
		}
	}
	return DeliveryPolicy{}, ErrUnknownPayloadPolicy
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
}

// BuildGuard constructs an EnvelopeGuard from the configuration or returns an error.
func (c GuardConfig) BuildGuard() (*EnvelopeGuard, error) {
	return NewEnvelopeGuard(c.Self, c.Parties, c.Protocol, c.SessionID, c.Policies, c.Cache)
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
