package tss

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/islishude/tss/internal/wire"
)

// Version is the library wire/protocol version used by current messages.
const Version = 1

const envelopeHashLabel = "github.com/islishude/tss/envelope/v1"

const envelopeWireType = "tss.envelope"

const (
	envelopeFieldProtocol uint16 = iota + 1
	envelopeFieldVersion
	envelopeFieldSessionID
	envelopeFieldRound
	envelopeFieldFrom
	envelopeFieldTo
	envelopeFieldPayloadType
	envelopeFieldPayload
	envelopeFieldTranscriptHash
)

// PartyID identifies one protocol participant; zero is reserved as "unset".
type PartyID uint32

// ProtocolID names a threshold signature protocol implemented by this module.
type ProtocolID string

const (
	// ProtocolCGGMP21Secp256k1 identifies the CGGMP21-style threshold ECDSA protocol.
	ProtocolCGGMP21Secp256k1 ProtocolID = "cggmp21-secp256k1"
	// ProtocolFROSTEd25519 identifies the FROST-style threshold Ed25519 protocol.
	ProtocolFROSTEd25519 ProtocolID = "frost-ed25519"
)

// PayloadType names a protocol message payload kind.
type PayloadType string

// Algorithm names a threshold signature algorithm implemented by this module.
type Algorithm string

const (
	// AlgorithmCGGMP21Secp256k1 identifies the CGGMP21-style threshold ECDSA package.
	AlgorithmCGGMP21Secp256k1 Algorithm = "cggmp21-secp256k1"
	// AlgorithmFROSTEd25519 identifies the FROST-style threshold Ed25519 package.
	AlgorithmFROSTEd25519 Algorithm = "frost-ed25519"
)

// PartySet is an ordered set of protocol participants.
type PartySet []PartyID

// Contains reports whether id is in the party set.
func (ps PartySet) Contains(id PartyID) bool {
	return ContainsParty(ps, id)
}

// Sorted returns a sorted copy of the party set.
func (ps PartySet) Sorted() PartySet {
	return SortParties(ps)
}

// Clone returns a deep copy of the party set.
func (ps PartySet) Clone() PartySet {
	return slices.Clone(ps)
}

// SecurityContext records transport-layer facts verified by the receiving adapter.
// It must NOT be set by protocol callers; only the transport receive path sets it.
type SecurityContext struct {
	Authenticated      bool
	Confidential       bool
	AuthenticatedParty PartyID
	ChannelID          string
	PeerKeyID          string
	ReceivedAtUnix     int64
}

// DeliveryMode classifies an envelope delivery path.
type DeliveryMode uint8

const (
	// DeliveryDirect is a point-to-point message addressed to a single recipient.
	DeliveryDirect DeliveryMode = iota
	// DeliveryBroadcast is a message sent to all parties.
	DeliveryBroadcast
)

// ConfidentialityPolicy specifies whether a message must be encrypted in transit.
type ConfidentialityPolicy uint8

const (
	// ConfidentialityForbidden means the message must NOT be sent over a confidential channel.
	ConfidentialityForbidden ConfidentialityPolicy = iota
	// ConfidentialityOptional means either plaintext or confidential transport is acceptable.
	ConfidentialityOptional
	// ConfidentialityRequired means the message MUST be sent over a confidential channel.
	ConfidentialityRequired
)

// BroadcastConsistencyPolicy specifies whether broadcast messages require a consistency certificate.
type BroadcastConsistencyPolicy uint8

const (
	// BroadcastConsistencyNone means no broadcast certificate is required.
	BroadcastConsistencyNone BroadcastConsistencyPolicy = iota
	// BroadcastConsistencyRequired means a valid BroadcastCertificate must be present.
	BroadcastConsistencyRequired
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

// ReplayKey uniquely identifies one protocol message for replay detection.
type ReplayKey struct {
	Protocol       ProtocolID
	SessionID      SessionID
	Round          uint8
	From           PartyID
	To             PartyID
	PayloadType    PayloadType
	TranscriptHash [32]byte
}

// ReplayCache detects replayed protocol messages.
// MarkIfNew returns true on first use of a key and false on subsequent uses.
type ReplayCache interface {
	MarkIfNew(key ReplayKey) bool
}

// BroadcastAck is one party's signed acknowledgment of a broadcast message.
type BroadcastAck struct {
	Party PartyID

	PayloadHash    [32]byte
	TranscriptHash [32]byte

	Signature []byte
}

// Clone returns a deep copy of the broadcast ack.
func (a BroadcastAck) Clone() BroadcastAck {
	return BroadcastAck{
		Party:          a.Party,
		PayloadHash:    a.PayloadHash,
		TranscriptHash: a.TranscriptHash,
		Signature:      slices.Clone(a.Signature),
	}
}

// BroadcastCertificate proves that all parties received the same broadcast payload.
type BroadcastCertificate struct {
	Protocol    ProtocolID
	SessionID   SessionID
	Round       uint8
	From        PartyID
	PayloadType PayloadType

	PayloadHash    [32]byte
	TranscriptHash [32]byte

	Recipients PartySet
	Acks       []BroadcastAck
}

// Clone returns a deep copy of the broadcast certificate.
func (c *BroadcastCertificate) Clone() *BroadcastCertificate {
	if c == nil {
		return nil
	}
	clone := *c
	clone.Recipients = c.Recipients.Clone()
	clone.Acks = cloneBroadcastAcks(c.Acks)
	return &clone
}

// Verify checks that the certificate binds to env and that
// every party acknowledged the same digest. It does not verify individual ack
// signatures; the caller must supply a verifier for that.
func (c *BroadcastCertificate) Verify(env Envelope, parties PartySet) error {
	if c == nil {
		return ErrMissingBroadcastCertificate
	}
	if c.Protocol != env.Protocol {
		return ErrInvalidBroadcastCertificate
	}
	if c.SessionID != env.SessionID {
		return ErrInvalidBroadcastCertificate
	}
	if c.Round != env.Round {
		return ErrInvalidBroadcastCertificate
	}
	if c.From != env.From {
		return ErrInvalidBroadcastCertificate
	}
	if c.PayloadType != env.PayloadType {
		return ErrInvalidBroadcastCertificate
	}
	if c.PayloadHash != sha256.Sum256(env.Payload) {
		return ErrInvalidBroadcastCertificate
	}
	if c.TranscriptHash != env.TranscriptHash {
		return ErrInvalidBroadcastCertificate
	}
	if len(c.Recipients) != len(parties) {
		return ErrInvalidBroadcastCertificate
	}
	for _, id := range parties {
		if !c.Recipients.Contains(id) {
			return ErrInvalidBroadcastCertificate
		}
	}
	if len(c.Acks) != len(parties) {
		return ErrInvalidBroadcastCertificate
	}
	seen := make(map[PartyID]bool, len(c.Acks))
	for _, ack := range c.Acks {
		if !parties.Contains(ack.Party) {
			return ErrInvalidBroadcastCertificate
		}
		if seen[ack.Party] {
			return ErrInvalidBroadcastCertificate
		}
		seen[ack.Party] = true
		if ack.PayloadHash != c.PayloadHash {
			return ErrInvalidBroadcastCertificate
		}
		if ack.TranscriptHash != c.TranscriptHash {
			return ErrInvalidBroadcastCertificate
		}
	}
	return nil
}

// EnvelopeInput carries the caller-provided fields for constructing an Envelope.
type EnvelopeInput struct {
	Protocol    ProtocolID
	Version     uint16
	SessionID   SessionID
	Round       uint8
	From        PartyID
	To          PartyID
	PayloadType PayloadType
	Payload     []byte
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

// SessionID is a 32-byte nonce that separates independent protocol executions.
type SessionID [32]byte

// NewSessionID returns a random session identifier from reader or crypto/rand.
func NewSessionID(reader io.Reader) (SessionID, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var id SessionID
	if _, err := io.ReadFull(reader, id[:]); err != nil {
		return SessionID{}, err
	}
	return id, nil
}

// SessionIDFromBytes parses a 32-byte session identifier.
func SessionIDFromBytes(in []byte) (SessionID, error) {
	var id SessionID
	if len(in) != len(id) {
		return id, fmt.Errorf("session id must be %d bytes", len(id))
	}
	copy(id[:], in)
	return id, nil
}

// Bytes returns a copy of the session identifier bytes.
func (id SessionID) Bytes() []byte {
	return slices.Clone(id[:])
}

// String returns the hex encoding of the session identifier.
func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalText encodes the session identifier as hex text.
func (id SessionID) MarshalText() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(id)))
	hex.Encode(out, id[:])
	return out, nil
}

// UnmarshalText decodes a hex session identifier.
func (id *SessionID) UnmarshalText(text []byte) error {
	raw, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	parsed, err := SessionIDFromBytes(raw)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// Valid reports whether the session identifier is non-zero.
func (id SessionID) Valid() bool {
	return id != (SessionID{})
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

// Envelope is a transport-neutral protocol message with transport-verified security context.
type Envelope struct {
	Protocol    ProtocolID
	Version     uint16
	SessionID   SessionID
	Round       uint8
	From        PartyID
	To          PartyID // zero means broadcast
	PayloadType PayloadType
	Payload     []byte

	TranscriptHash [32]byte

	Security SecurityContext

	Broadcast *BroadcastCertificate
}

// Clone returns a deep copy of the envelope.
func (e Envelope) Clone() Envelope {
	clone := Envelope{
		Protocol:       e.Protocol,
		Version:        e.Version,
		SessionID:      e.SessionID,
		Round:          e.Round,
		From:           e.From,
		To:             e.To,
		PayloadType:    e.PayloadType,
		Payload:        append([]byte(nil), e.Payload...),
		TranscriptHash: e.TranscriptHash,
		Security:       e.Security,
		Broadcast:      e.Broadcast.Clone(),
	}
	return clone
}

// cloneBroadcastAcks returns a deep copy of a broadcast ack slice.
func cloneBroadcastAcks(acks []BroadcastAck) []BroadcastAck {
	if acks == nil {
		return nil
	}
	out := make([]BroadcastAck, len(acks))
	for i, ack := range acks {
		out[i] = ack.Clone()
	}
	return out
}

// MarshalBinary encodes the envelope using strict canonical TLV wire format.
// It rejects locally-constructed payloads that exceed size limits.
func (e Envelope) MarshalBinary() ([]byte, error) {
	limits := DefaultLimits()
	if e.Protocol == "" {
		return nil, errors.New("envelope protocol is empty")
	}
	if len(e.Protocol) > limits.MaxProtocolNameBytes {
		return nil, fmt.Errorf("envelope protocol name too long: %d > %d", len(e.Protocol), limits.MaxProtocolNameBytes)
	}
	if e.Version != Version {
		return nil, fmt.Errorf("unexpected envelope version %d", e.Version)
	}
	if e.PayloadType == "" {
		return nil, errors.New("envelope payload type is empty")
	}
	if len(e.PayloadType) > limits.MaxPayloadTypeBytes {
		return nil, fmt.Errorf("envelope payload type too long: %d > %d", len(e.PayloadType), limits.MaxPayloadTypeBytes)
	}
	if len(e.Payload) > limits.MaxEnvelopePayloadBytes {
		return nil, fmt.Errorf("envelope payload too large: %d > %d", len(e.Payload), limits.MaxEnvelopePayloadBytes)
	}
	return wire.Marshal(Version, envelopeWireType, []wire.Field{
		{Tag: envelopeFieldProtocol, Value: []byte(e.Protocol)},
		{Tag: envelopeFieldVersion, Value: wire.Uint16(e.Version)},
		{Tag: envelopeFieldSessionID, Value: e.SessionID[:]},
		{Tag: envelopeFieldRound, Value: []byte{e.Round}},
		{Tag: envelopeFieldFrom, Value: wire.Uint32(uint32(e.From))},
		{Tag: envelopeFieldTo, Value: wire.Uint32(uint32(e.To))},
		{Tag: envelopeFieldPayloadType, Value: []byte(e.PayloadType)},
		{Tag: envelopeFieldPayload, Value: wire.NonNilBytes(e.Payload)},
		{Tag: envelopeFieldTranscriptHash, Value: e.TranscriptHash[:]},
	})
}

// UnmarshalBinary decodes a canonical TLV envelope and rejects JSON fallback.
// It enforces total size, per-field size, and metadata length limits.
func (e *Envelope) UnmarshalBinary(in []byte) error {
	limits := DefaultLimits()

	if len(in) == 0 {
		return errors.New("empty envelope")
	}
	if len(in) > limits.MaxEnvelopeBytes {
		return fmt.Errorf("envelope too large: %d > %d", len(in), limits.MaxEnvelopeBytes)
	}

	version, fields, err := wire.UnmarshalWithLimits(in, envelopeWireType, wire.Limits{
		MaxTotalBytes: limits.MaxEnvelopeBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})
	if err != nil {
		return err
	}
	if version != Version {
		return fmt.Errorf("unexpected envelope wire version %d", version)
	}
	protocol, err := wire.Require(fields, envelopeFieldProtocol)
	if err != nil {
		return err
	}
	if len(protocol) == 0 {
		return errors.New("envelope protocol is empty")
	}
	if len(protocol) > limits.MaxProtocolNameBytes {
		return fmt.Errorf("envelope protocol name too long: %d > %d", len(protocol), limits.MaxProtocolNameBytes)
	}
	versionBytes, err := wire.Require(fields, envelopeFieldVersion)
	if err != nil {
		return err
	}
	envVersion, err := wire.DecodeUint16(versionBytes)
	if err != nil {
		return fmt.Errorf("invalid envelope version field: %w", err)
	}
	if envVersion != Version {
		return fmt.Errorf("unexpected envelope version %d", envVersion)
	}
	sessionBytes, err := wire.Require(fields, envelopeFieldSessionID)
	if err != nil {
		return err
	}
	session, err := SessionIDFromBytes(sessionBytes)
	if err != nil {
		return err
	}
	round, err := wire.Require(fields, envelopeFieldRound)
	if err != nil {
		return err
	}
	if len(round) != 1 {
		return errors.New("invalid envelope round")
	}
	fromBytes, err := wire.Require(fields, envelopeFieldFrom)
	if err != nil {
		return err
	}
	from, err := wire.DecodeUint32(fromBytes)
	if err != nil {
		return fmt.Errorf("invalid envelope sender: %w", err)
	}
	toBytes, err := wire.Require(fields, envelopeFieldTo)
	if err != nil {
		return err
	}
	to, err := wire.DecodeUint32(toBytes)
	if err != nil {
		return fmt.Errorf("invalid envelope recipient: %w", err)
	}
	payloadType, err := wire.Require(fields, envelopeFieldPayloadType)
	if err != nil {
		return err
	}
	if len(payloadType) == 0 {
		return errors.New("envelope payload type is empty")
	}
	if len(payloadType) > limits.MaxPayloadTypeBytes {
		return fmt.Errorf("envelope payload type too long: %d > %d", len(payloadType), limits.MaxPayloadTypeBytes)
	}
	payload, err := wire.Require(fields, envelopeFieldPayload)
	if err != nil {
		return err
	}
	if len(payload) > limits.MaxEnvelopePayloadBytes {
		return fmt.Errorf("envelope payload too large: %d > %d", len(payload), limits.MaxEnvelopePayloadBytes)
	}
	transcript, err := wire.Require(fields, envelopeFieldTranscriptHash)
	if err != nil {
		return err
	}
	var transcriptHash [32]byte
	if len(transcript) > 0 {
		if len(transcript) != sha256.Size {
			return errors.New("invalid envelope transcript hash")
		}
		copy(transcriptHash[:], transcript)
	}
	*e = Envelope{
		Protocol:       ProtocolID(protocol),
		Version:        envVersion,
		SessionID:      session,
		Round:          round[0],
		From:           PartyID(from),
		To:             PartyID(to),
		PayloadType:    PayloadType(payloadType),
		Payload:        payload,
		TranscriptHash: transcriptHash,
	}
	return nil
}

// NewEnvelope constructs an envelope from caller-provided fields.
// It validates basic fields, canonical-encodes the payload, and computes the transcript hash.
func NewEnvelope(input EnvelopeInput) (Envelope, error) {
	if input.Protocol == "" {
		return Envelope{}, errors.New("envelope protocol is empty")
	}
	if input.Version != Version {
		return Envelope{}, fmt.Errorf("unexpected envelope version %d", input.Version)
	}
	if input.PayloadType == "" {
		return Envelope{}, errors.New("envelope payload type is empty")
	}
	limits := DefaultLimits()
	if len(input.Protocol) > limits.MaxProtocolNameBytes {
		return Envelope{}, fmt.Errorf("envelope protocol name too long: %d > %d", len(input.Protocol), limits.MaxProtocolNameBytes)
	}
	if len(input.PayloadType) > limits.MaxPayloadTypeBytes {
		return Envelope{}, fmt.Errorf("envelope payload type too long: %d > %d", len(input.PayloadType), limits.MaxPayloadTypeBytes)
	}
	if len(input.Payload) > limits.MaxEnvelopePayloadBytes {
		return Envelope{}, fmt.Errorf("envelope payload too large: %d > %d", len(input.Payload), limits.MaxEnvelopePayloadBytes)
	}
	e := Envelope{
		Protocol:    input.Protocol,
		Version:     input.Version,
		SessionID:   input.SessionID,
		Round:       input.Round,
		From:        input.From,
		To:          input.To,
		PayloadType: input.PayloadType,
		Payload:     input.Payload,
	}
	e.TranscriptHash = e.domainSeparatedHash()
	return e, nil
}

// OpenEnvelope decodes a wire envelope and attaches transport-verified security context.
// It recomputes the transcript hash from the wire bytes and stores the provided
// SecurityContext and BroadcastCertificate. No protocol policy checks are performed.
func OpenEnvelope(raw []byte, security SecurityContext, broadcast *BroadcastCertificate) (Envelope, error) {
	var env Envelope
	if err := env.UnmarshalBinary(raw); err != nil {
		return Envelope{}, err
	}
	// Recompute transcript hash from wire-decoded fields.
	env.TranscriptHash = env.domainSeparatedHash()
	env.Security = security
	env.Broadcast = broadcast
	return env, nil
}

// DomainSeparatedHash hashes the public envelope metadata and payload.
func (e Envelope) DomainSeparatedHash() []byte {
	hash := e.domainSeparatedHash()
	return hash[:]
}

func (e Envelope) domainSeparatedHash() [32]byte {
	h := sha256.New()
	// The protocol/version/session/round tuple keeps transcripts from one
	// algorithm or session from being replayed into another.
	h.Write([]byte(envelopeHashLabel))
	h.Write([]byte{0})
	h.Write([]byte(e.Protocol))
	h.Write([]byte{0, byte(e.Version >> 8), byte(e.Version), e.Round})
	h.Write(e.SessionID[:])
	h.Write(wire.Uint32(uint32(e.From)))
	h.Write(wire.Uint32(uint32(e.To)))
	h.Write([]byte(e.PayloadType))
	h.Write([]byte{0})
	h.Write(e.Payload)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// VerifyTranscriptHash recomputes the transcript hash and compares it against the stored value.
func VerifyTranscriptHash(env Envelope) error {
	want := env.domainSeparatedHash()
	if want != env.TranscriptHash {
		return errors.New("transcript hash mismatch")
	}
	return nil
}

// RecomputeTranscriptHash returns a copy of the envelope with the transcript hash recomputed.
// This is intended for tests that mutate envelope fields; production code should use NewEnvelope.
func (e Envelope) RecomputeTranscriptHash() Envelope {
	e.TranscriptHash = e.domainSeparatedHash()
	return e
}

// ValidateEnvelope performs common envelope validation without a guard.
// This is a transitional helper for handlers that have not yet adopted EnvelopeGuard.
// New code should use EnvelopeGuard.Validate instead.
func ValidateEnvelope(env Envelope, expectedProtocol ProtocolID, expectedSession SessionID, parties []PartyID) error {
	if env.Protocol != expectedProtocol {
		return fmt.Errorf("unexpected protocol %q", env.Protocol)
	}
	if env.Version != Version {
		return fmt.Errorf("unexpected version %d", env.Version)
	}
	if env.SessionID != expectedSession {
		return errors.New("session mismatch")
	}
	if err := VerifyTranscriptHash(env); err != nil {
		return err
	}
	if len(parties) > 0 && !ContainsParty(parties, env.From) {
		return fmt.Errorf("sender %d is not a participant", env.From)
	}
	return nil
}

// ValidateEnvelopePolicy checks delivery mode and confidentiality against a PolicySet.
// It is a lightweight complement to ValidateEnvelope for the test fallback path
// (when no EnvelopeGuard is set and the transport is unauthenticated).
// It does NOT check broadcast consistency or replay — those require guard infrastructure.
func ValidateEnvelopePolicy(env Envelope, self PartyID, policies PolicySet) error {
	policy, err := policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return err
	}

	// Delivery mode enforcement.
	switch policy.Mode {
	case DeliveryDirect:
		if env.To == 0 {
			return fmt.Errorf("%w: %s", ErrExpectedDirectMessage, env.PayloadType)
		}
		if env.To != self {
			return fmt.Errorf("%w: expected %d, got %d", ErrWrongRecipient, self, env.To)
		}
	case DeliveryBroadcast:
		if env.To != 0 {
			return fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, env.PayloadType)
		}
	}

	// Confidentiality enforcement.
	// ConfidentialityRequired is always checked — even unauthenticated test
	// transports must set Security.Confidential for secret-bearing payloads.
	// ConfidentialityForbidden is only checked when the transport is
	// authenticated, since a zero-value Security is already non-confidential.
	switch policy.Confidentiality {
	case ConfidentialityRequired:
		if !env.Security.Confidential {
			return fmt.Errorf("%w: %s", ErrMissingConfidentiality, env.PayloadType)
		}
	case ConfidentialityForbidden:
		if env.Security.Authenticated && env.Security.Confidential {
			return fmt.Errorf("%w: %s", ErrUnexpectedConfidentiality, env.PayloadType)
		}
	}

	return nil
}

// KeyShare is the common interface implemented by algorithm-specific shares.
type KeyShare interface {
	Algorithm() Algorithm
	PartyID() PartyID
	PublicKeyBytes() []byte
	MarshalBinary() ([]byte, error)
	Destroy()
}

// Signature is the common transport shape for algorithm-specific signatures.
type Signature struct {
	Algorithm Algorithm `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	Data      []byte    `json:"data"`
	R         []byte    `json:"r,omitempty"`
	S         []byte    `json:"s,omitempty"`
}

// Blame identifies parties and public evidence associated with a protocol failure.
type Blame struct {
	Reason   string    `json:"reason"`
	Parties  []PartyID `json:"parties"`
	Evidence []byte    `json:"evidence,omitempty"`
}

// ContainsParty reports whether id appears in parties.
func ContainsParty(parties []PartyID, id PartyID) bool {
	return slices.Contains(parties, id)
}

// SortParties returns a sorted copy of parties.
func SortParties(parties []PartyID) []PartyID {
	out := slices.Clone(parties)
	slices.Sort(out)
	return out
}

// ValidateSignerSet checks signers against a key's participant set and limits.
// It verifies: non-empty, minimum size (threshold), maximum size, membership,
// and no duplicates. For algorithms where AllowOversizedSignerSet is false,
// signer count must exactly equal threshold.
func ValidateSignerSet(keyParties []PartyID, threshold int, signers []PartyID, limits Limits) error {
	if len(signers) == 0 {
		return errors.New("signers must not be empty")
	}
	if len(signers) < threshold {
		return fmt.Errorf("not enough signers: %d < threshold %d", len(signers), threshold)
	}
	if len(signers) > limits.MaxSigners {
		return fmt.Errorf("too many signers: %d > %d", len(signers), limits.MaxSigners)
	}
	if !limits.AllowOversizedSignerSet && len(signers) != threshold {
		return fmt.Errorf("signer count must equal threshold: got %d, want %d", len(signers), threshold)
	}
	seen := make(map[PartyID]struct{}, len(signers))
	for _, id := range signers {
		if !ContainsParty(keyParties, id) {
			return fmt.Errorf("signer %d is not a participant", id)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate signer %d", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// AggregateChainCode XORs the 32-byte chain code from each party to produce the
// group chain code. The caller is responsible for checking whether HD is enabled;
// this function requires every party to contribute exactly 32 bytes.
func AggregateChainCode(parties []PartyID, chainCodes map[PartyID][]byte) ([]byte, error) {
	out := make([]byte, 32)
	for _, id := range parties {
		if len(chainCodes[id]) != 32 {
			return nil, fmt.Errorf("party %d chain code is %d bytes, want 32", id, len(chainCodes[id]))
		}
		for i := range out {
			out[i] ^= chainCodes[id][i]
		}
	}
	return out, nil
}
