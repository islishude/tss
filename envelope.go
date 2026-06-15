package tss

import (
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

// Envelope is a transport-neutral protocol wire message.
type Envelope struct {
	Protocol    ProtocolID  `wire:"1,string"`
	Version     uint16      `wire:"2,u16"`
	SessionID   SessionID   `wire:"3,bytes,len=32"`
	Round       uint8       `wire:"4,u8"`
	From        PartyID     `wire:"5,u32"`
	To          PartyID     `wire:"6,u32"` // zero means broadcast
	PayloadType PayloadType `wire:"7,string"`
	Payload     []byte      `wire:"8,bytes"`

	TranscriptHash [32]byte `wire:"9,bytes,len=32"`
}

// ChannelProtection describes the channel protection actually observed by the
// receive transport. The zero value is invalid and fails closed.
type ChannelProtection uint8

const (
	// ChannelProtectionUnknown means the receive path did not report channel protection.
	ChannelProtectionUnknown ChannelProtection = iota
	// ChannelPlaintext means the receive path explicitly observed plaintext delivery.
	ChannelPlaintext
	// ChannelConfidential means the receive path explicitly observed confidential delivery.
	ChannelConfidential
)

// ReceiveInfo records transport-verified facts for a received envelope.
type ReceiveInfo struct {
	Peer       PartyID
	Protection ChannelProtection
	ChannelID  string
	PeerKeyID  string
	ReceivedAt time.Time
}

// InboundEnvelope is a received envelope bound to transport-verified facts.
//
// Its fields are intentionally unexported so callers cannot mutate wire data or
// receive facts after opening and validation.
type InboundEnvelope struct {
	env         Envelope
	receiveInfo ReceiveInfo
	broadcast   *BroadcastCertificate
}

// WireType returns the canonical wire type identifier for Envelope.
func (Envelope) WireType() string { return envelopeWireType }

// WireVersion returns the wire format version for Envelope.
func (Envelope) WireVersion() uint16 { return Version }

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
	}
	return clone
}

// Envelope returns a deep copy of the inbound wire envelope.
func (in InboundEnvelope) Envelope() Envelope {
	return in.env.Clone()
}

// ReceiveInfo returns a copy of the transport receive facts.
func (in InboundEnvelope) ReceiveInfo() ReceiveInfo {
	return in.receiveInfo
}

// BroadcastCertificate returns a deep copy of the attached broadcast certificate.
func (in InboundEnvelope) BroadcastCertificate() *BroadcastCertificate {
	return in.broadcast.Clone()
}

// Protocol returns the envelope protocol identifier.
func (in InboundEnvelope) Protocol() ProtocolID {
	return in.env.Protocol
}

// Version returns the envelope wire version.
func (in InboundEnvelope) Version() uint16 {
	return in.env.Version
}

// SessionID returns the envelope session ID.
func (in InboundEnvelope) SessionID() SessionID {
	return in.env.SessionID
}

// Round returns the protocol round.
func (in InboundEnvelope) Round() uint8 {
	return in.env.Round
}

// From returns the sender party ID from the wire envelope.
func (in InboundEnvelope) From() PartyID {
	return in.env.From
}

// To returns the recipient party ID from the wire envelope, or zero for broadcast.
func (in InboundEnvelope) To() PartyID {
	return in.env.To
}

// PayloadType returns the payload type name.
func (in InboundEnvelope) PayloadType() PayloadType {
	return in.env.PayloadType
}

// Payload returns a copy of the envelope payload bytes.
func (in InboundEnvelope) Payload() []byte {
	return append([]byte(nil), in.env.Payload...)
}

// TranscriptHash returns the envelope transcript hash.
func (in InboundEnvelope) TranscriptHash() [32]byte {
	return in.env.TranscriptHash
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

// defaultEnvelopeLimits returns conservative envelope limits suitable for
// production use. Callers that need different limits should use
// MarshalEnvelopeWithLimits / UnmarshalEnvelopeWithLimits directly.
func defaultEnvelopeLimits() EnvelopeLimits {
	return EnvelopeLimits{
		MaxBytes:             DefaultMaxEnvelopeBytes,
		MaxPayloadBytes:      DefaultMaxEnvelopePayloadBytes,
		MaxPayloadTypeBytes:  DefaultMaxPayloadTypeBytes,
		MaxProtocolNameBytes: DefaultMaxProtocolNameBytes,
		TLV: TLVLimits{
			MaxFields:     DefaultMaxWireFields,
			MaxFieldBytes: DefaultMaxWireFieldBytes,
		},
	}
}

// validateEnvelopeFields checks per-field limits that are not covered by wire
// encoding (string lengths, payload size, session id validity).
func validateEnvelopeFields(env *Envelope, limits EnvelopeLimits) error {
	if env.Protocol == "" {
		return errors.New("envelope protocol is empty")
	}
	if len(env.Protocol) > limits.MaxProtocolNameBytes {
		return fmt.Errorf("envelope protocol name too long: %d > %d", len(env.Protocol), limits.MaxProtocolNameBytes)
	}
	if env.Version != Version {
		return fmt.Errorf("unexpected envelope version %d", env.Version)
	}
	if env.PayloadType == "" {
		return errors.New("envelope payload type is empty")
	}
	if len(env.PayloadType) > limits.MaxPayloadTypeBytes {
		return fmt.Errorf("envelope payload type too long: %d > %d", len(env.PayloadType), limits.MaxPayloadTypeBytes)
	}
	if len(env.Payload) > limits.MaxPayloadBytes {
		return fmt.Errorf("envelope payload too large: %d > %d", len(env.Payload), limits.MaxPayloadBytes)
	}
	if !env.SessionID.Valid() {
		return errors.New("invalid session id")
	}
	if env.From == 0 {
		return errors.New("envelope sender is zero (unset)")
	}
	return nil
}

// MarshalBinary encodes the envelope using the object-level wire codec with
// conservative default limits. Use [MarshalEnvelopeWithLimits] for explicit control.
func (e Envelope) MarshalBinary() ([]byte, error) {
	return MarshalEnvelopeWithLimits(e, defaultEnvelopeLimits())
}

// MarshalEnvelopeWithLimits encodes the envelope using the object-level wire
// codec, enforcing the provided size limits.
func MarshalEnvelopeWithLimits(env Envelope, limits EnvelopeLimits) ([]byte, error) {
	if err := validateEnvelopeFields(&env, limits); err != nil {
		return nil, err
	}
	return wire.Marshal(env)
}

// UnmarshalBinary decodes a canonical TLV envelope using the object-level wire codec
// with conservative default limits. Use [UnmarshalEnvelopeWithLimits] for explicit control.
func (e *Envelope) UnmarshalBinary(in []byte) error {
	env, err := UnmarshalEnvelopeWithLimits(in, defaultEnvelopeLimits())
	if err != nil {
		return err
	}
	*e = env
	return nil
}

// UnmarshalEnvelopeWithLimits decodes a canonical TLV envelope enforcing the
// provided size limits. It returns a decoded envelope or an error.
func UnmarshalEnvelopeWithLimits(in []byte, limits EnvelopeLimits) (Envelope, error) {
	if len(in) == 0 {
		return Envelope{}, errors.New("empty envelope")
	}
	if len(in) > limits.MaxBytes {
		return Envelope{}, fmt.Errorf("envelope too large: %d > %d", len(in), limits.MaxBytes)
	}
	var env Envelope
	if err := wire.Unmarshal(in, &env, wire.WithFrameLimits(wire.FrameLimits{
		MaxTotalBytes: limits.MaxBytes,
		MaxFields:     limits.TLV.MaxFields,
		MaxFieldBytes: limits.TLV.MaxFieldBytes,
	})); err != nil {
		return Envelope{}, err
	}
	if err := validateEnvelopeFields(&env, limits); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// NewEnvelope constructs an envelope from caller-provided fields using
// conservative default limits. Use [NewEnvelopeWithLimits] for explicit control.
func NewEnvelope(input EnvelopeInput) (Envelope, error) {
	return NewEnvelopeWithLimits(input, defaultEnvelopeLimits())
}

// NewEnvelopeWithLimits constructs an envelope from caller-provided fields,
// enforcing the provided size limits. It validates basic fields, canonical-encodes
// the payload, and computes the transcript hash.
func NewEnvelopeWithLimits(input EnvelopeInput, limits EnvelopeLimits) (Envelope, error) {
	if input.Protocol == "" {
		return Envelope{}, errors.New("envelope protocol is empty")
	}
	if input.Version != Version {
		return Envelope{}, fmt.Errorf("unexpected envelope version %d", input.Version)
	}
	if input.PayloadType == "" {
		return Envelope{}, errors.New("envelope payload type is empty")
	}
	if len(input.Protocol) > limits.MaxProtocolNameBytes {
		return Envelope{}, fmt.Errorf("envelope protocol name too long: %d > %d", len(input.Protocol), limits.MaxProtocolNameBytes)
	}
	if len(input.PayloadType) > limits.MaxPayloadTypeBytes {
		return Envelope{}, fmt.Errorf("envelope payload type too long: %d > %d", len(input.PayloadType), limits.MaxPayloadTypeBytes)
	}
	if len(input.Payload) > limits.MaxPayloadBytes {
		return Envelope{}, fmt.Errorf("envelope payload too large: %d > %d", len(input.Payload), limits.MaxPayloadBytes)
	}
	if !input.SessionID.Valid() {
		return Envelope{}, ErrInvalidSessionID
	}
	if input.From == 0 {
		return Envelope{}, errors.New("envelope sender is zero (unset)")
	}
	e := Envelope{
		Protocol:    input.Protocol,
		Version:     input.Version,
		SessionID:   input.SessionID,
		Round:       input.Round,
		From:        input.From,
		To:          input.To,
		PayloadType: input.PayloadType,
		Payload:     append([]byte(nil), input.Payload...),
	}
	e.TranscriptHash = e.domainSeparatedHash()
	return e, nil
}

type openOptions struct {
	limits    EnvelopeLimits
	broadcast *BroadcastCertificate
}

// OpenOption configures OpenEnvelope.
type OpenOption func(*openOptions)

// WithBroadcastCertificate attaches a transport-collected broadcast certificate
// to the opened inbound envelope. OpenEnvelope deep-clones the certificate before
// storing it, so the caller retains ownership of the original.
func WithBroadcastCertificate(cert *BroadcastCertificate) OpenOption {
	return func(opts *openOptions) {
		opts.broadcast = cert
	}
}

// WithEnvelopeLimits configures explicit envelope size limits while opening.
func WithEnvelopeLimits(limits EnvelopeLimits) OpenOption {
	return func(opts *openOptions) {
		opts.limits = limits
	}
}

// OpenEnvelope decodes a wire envelope and binds it to transport-verified receive facts.
// It recomputes the transcript hash from the wire-decoded fields. Protocol policy
// checks are performed later by EnvelopeGuard.
func OpenEnvelope(raw []byte, info ReceiveInfo, opts ...OpenOption) (InboundEnvelope, error) {
	options := openOptions{limits: defaultEnvelopeLimits()}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	env, err := UnmarshalEnvelopeWithLimits(raw, options.limits)
	if err != nil {
		return InboundEnvelope{}, err
	}
	// Recompute transcript hash from wire-decoded fields.
	env.TranscriptHash = env.domainSeparatedHash()
	if info.Peer == 0 {
		return InboundEnvelope{}, ErrUnauthenticatedTransport
	}
	if info.Protection == ChannelProtectionUnknown {
		return InboundEnvelope{}, ErrMissingChannelProtection
	}
	if info.Peer != env.From {
		return InboundEnvelope{}, fmt.Errorf("%w: authenticated %d, envelope from %d", ErrSenderIdentityMismatch, info.Peer, env.From)
	}
	if info.ReceivedAt.IsZero() {
		info.ReceivedAt = time.Now()
	}
	return InboundEnvelope{
		env:         env.Clone(),
		receiveInfo: info,
		broadcast:   options.broadcast.Clone(),
	}, nil
}

// OpenEnvelopeWithLimits decodes a wire envelope with explicit limits and binds
// it to transport-verified receive facts.
func OpenEnvelopeWithLimits(raw []byte, info ReceiveInfo, limits EnvelopeLimits, opts ...OpenOption) (InboundEnvelope, error) {
	options := append([]OpenOption{WithEnvelopeLimits(limits)}, opts...)
	return OpenEnvelope(raw, info, options...)
}

// DomainSeparatedHash hashes the public envelope metadata and payload.
func (e Envelope) DomainSeparatedHash() []byte {
	hash := e.domainSeparatedHash()
	return hash[:]
}

func (e Envelope) domainSeparatedHash() [32]byte {
	// The protocol/version/session/round tuple keeps transcripts from one
	// algorithm or session from being replayed into another.
	t := transcript.New(envelopeHashLabel)
	t.AppendString("protocol", string(e.Protocol))
	t.AppendUint16("version", e.Version)
	t.AppendBytes("session_id", e.SessionID[:])
	t.AppendUint8("round", e.Round)
	t.AppendUint32("from", e.From)
	t.AppendUint32("to", e.To)
	t.AppendString("payload_type", string(e.PayloadType))
	t.AppendBytes("payload", e.Payload)
	return t.Sum32()
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

// ValidateEnvelopePolicy checks delivery mode and confidentiality against a PolicySet.
// It is a lightweight complement for the test fallback path (when no EnvelopeGuard
// is set and the transport is unauthenticated). It does NOT check broadcast
// consistency or replay — those require guard infrastructure.
func ValidateEnvelopePolicy(env InboundEnvelope, self PartyID, policies PolicySet) error {
	protocol := env.Protocol()
	pt := env.PayloadType()
	policy, err := policies.Match(protocol, env.Round(), pt)
	if err != nil {
		return err
	}

	// Delivery mode enforcement.
	switch policy.Mode {
	case DeliveryDirect:
		if to := env.To(); to == 0 {
			return fmt.Errorf("%w: %s", ErrExpectedDirectMessage, pt)
		} else if to != self {
			return fmt.Errorf("%w: expected %d, got %d", ErrWrongRecipient, self, to)
		}
	case DeliveryBroadcast:
		if env.To() != 0 {
			return fmt.Errorf("%w: %s", ErrExpectedBroadcastMessage, pt)
		}
	}

	// Confidentiality enforcement.
	// Both ConfidentialityRequired and ConfidentialityForbidden are checked
	// against the channel protection reported by the receive path.
	switch policy.Confidentiality {
	case ConfidentialityRequired:
		if env.ReceiveInfo().Protection != ChannelConfidential {
			return fmt.Errorf("%w: %s", ErrMissingConfidentiality, pt)
		}
	case ConfidentialityForbidden:
		if env.ReceiveInfo().Protection == ChannelConfidential {
			return fmt.Errorf("%w: %s", ErrUnexpectedConfidentiality, pt)
		}
	}

	return nil
}
