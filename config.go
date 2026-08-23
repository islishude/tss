package tss

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/islishude/tss/internal/transcript"
)

// DeliveryPolicy defines the transport requirements for one protocol message kind.
type DeliveryPolicy struct {
	Protocol    ProtocolID
	Round       uint8
	PayloadType PayloadType

	Mode DeliveryMode

	Confidentiality ConfidentialityPolicy

	BroadcastConsistency BroadcastConsistencyPolicy

	// RequireSenderSignature requires portable sender authentication in
	// addition to transport authentication.
	RequireSenderSignature bool
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
	entries  []DeliveryPolicy
	index    map[policyKey]int // maps key → index into entries
	testOnly bool
}

// NewPolicySet builds a PolicySet from a list of delivery policies.
// It clones the input slice so callers cannot mutate the policy entries
// after construction. Duplicate keys are rejected.
func NewPolicySet(policies ...DeliveryPolicy) (PolicySet, error) {
	return newPolicySet(false, policies...)
}

// NewTestPolicySet builds a structurally valid policy set whose mandatory
// broadcast-consistency or sender-signature requirements may be relaxed for
// deterministic tests. It panics outside a Go test binary and production
// guards reject the returned set.
func NewTestPolicySet(policies ...DeliveryPolicy) (PolicySet, error) {
	if !testing.Testing() {
		panic("NewTestPolicySet must only be called from tests")
	}
	return newPolicySet(true, policies...)
}

func newPolicySet(testOnly bool, policies ...DeliveryPolicy) (PolicySet, error) {
	if len(policies) == 0 {
		return PolicySet{}, errors.New("delivery policy set must not be empty")
	}
	cloned := slices.Clone(policies)
	idx := make(map[policyKey]int, len(cloned))
	for i, p := range cloned {
		if err := validateDeliveryPolicy(p, testOnly); err != nil {
			return PolicySet{}, err
		}
		k := policyKey{protocol: p.Protocol, round: p.Round, payloadType: p.PayloadType}
		if _, exists := idx[k]; exists {
			return PolicySet{}, fmt.Errorf("duplicate delivery policy for protocol=%q round=%d payloadType=%q", p.Protocol, p.Round, p.PayloadType)
		}
		idx[k] = i
	}
	return PolicySet{entries: cloned, index: idx, testOnly: testOnly}, nil
}

func validateDeliveryPolicy(p DeliveryPolicy, testOnly bool) error {
	if p.Protocol == "" || p.PayloadType == "" {
		return errors.New("delivery policy protocol and payload type must not be empty")
	}
	if p.Mode != DeliveryDirect && p.Mode != DeliveryBroadcast {
		return fmt.Errorf("invalid delivery mode %d for %q", p.Mode, p.PayloadType)
	}
	if p.Confidentiality > ConfidentialityRequired {
		return fmt.Errorf("invalid confidentiality policy %d for %q", p.Confidentiality, p.PayloadType)
	}
	if p.BroadcastConsistency > BroadcastConsistencyRequired {
		return fmt.Errorf("invalid broadcast consistency policy %d for %q", p.BroadcastConsistency, p.PayloadType)
	}
	if p.Mode == DeliveryDirect && p.BroadcastConsistency != BroadcastConsistencyNone {
		return fmt.Errorf("direct message %q must not require a broadcast certificate", p.PayloadType)
	}
	if !testOnly && p.Mode == DeliveryBroadcast && p.BroadcastConsistency != BroadcastConsistencyRequired {
		return fmt.Errorf("broadcast message %q must require broadcast consistency", p.PayloadType)
	}
	return nil
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

// Digest returns the canonical delivery-policy digest. Registration order does
// not affect the result; every field that changes guard behavior is bound.
func (ps PolicySet) Digest() [32]byte {
	entries := slices.Clone(ps.entries)
	slices.SortFunc(entries, func(a, b DeliveryPolicy) int {
		if n := cmp.Compare(a.Protocol, b.Protocol); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Round, b.Round); n != 0 {
			return n
		}
		return cmp.Compare(a.PayloadType, b.PayloadType)
	})
	t := transcript.New("tss-delivery-policy")
	for _, p := range entries {
		t.AppendString("protocol", string(p.Protocol))
		t.AppendUint8("round", p.Round)
		t.AppendString("payload_type", string(p.PayloadType))
		t.AppendUint8("mode", uint8(p.Mode))
		t.AppendUint8("confidentiality", uint8(p.Confidentiality))
		t.AppendUint8("broadcast_consistency", uint8(p.BroadcastConsistency))
		t.AppendBool("require_sender_signature", p.RequireSenderSignature)
	}
	return t.Sum32()
}

func (ps PolicySet) valid() bool {
	return len(ps.entries) != 0 && ps.index != nil
}

func (ps PolicySet) requiresSenderSignature() bool {
	for _, p := range ps.entries {
		if p.RequireSenderSignature {
			return true
		}
	}
	return false
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
	return ps
}

// Entries returns a copy of the policy entries in registration order.
func (ps PolicySet) Entries() []DeliveryPolicy {
	return slices.Clone(ps.entries)
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
	// EnvelopeVerifier verifies portable sender signatures required by policy.
	EnvelopeVerifier EnvelopeSignatureVerifier
}

// BuildGuard constructs an EnvelopeGuard from the configuration or returns an error.
// Production deployments must provide a non-nil AckVerifier; test code should use
// [NewTestEnvelopeGuard] instead.
func (c GuardConfig) BuildGuard() (*EnvelopeGuard, error) {
	if c.Policies.testOnly {
		return nil, errors.New("test-only delivery policy cannot build a production guard")
	}
	if c.AckVerifier == nil {
		return nil, ErrMissingAckVerifier
	}
	if c.Policies.requiresSenderSignature() && c.EnvelopeVerifier == nil {
		return nil, ErrMissingEnvelopeSignatureVerifier
	}
	return newEnvelopeGuard(
		c.Self,
		c.Parties,
		c.Protocol,
		c.SessionID,
		c.Policies,
		c.Cache,
		c.AckVerifier,
		c.EnvelopeVerifier,
		false,
	)
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
	Threshold      int
	Parties        PartySet
	Self           PartyID
	SessionID      SessionID
	Rand           io.Reader       `json:"-"`
	Context        context.Context `json:"-"`
	Log            Logger          `json:"-"`
	EnvelopeSigner EnvelopeSigner  `json:"-"`
}

// LocalConfig contains per-process runtime configuration for one protocol
// participant. Consensus parameters such as threshold, party set, session ID,
// signer set, derivation context, and HD enablement belong in protocol-specific
// plan objects, not in LocalConfig.
type LocalConfig struct {
	Self           PartyID
	Rand           io.Reader       `json:"-"`
	Context        context.Context `json:"-"`
	Log            Logger          `json:"-"`
	EnvelopeSigner EnvelopeSigner  `json:"-"`
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

// CheckHandlerContext checks both the per-delivery context and the session
// context. Protocol handlers call it at state-transition boundaries; it does
// not claim to interrupt one indivisible cryptographic operation.
func CheckHandlerContext(delivery, session context.Context) error {
	if delivery == nil {
		return errors.New("nil handler context")
	}
	if err := delivery.Err(); err != nil {
		return err
	}
	if session != nil {
		return session.Err()
	}
	return nil
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
