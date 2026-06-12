package tss

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

// Envelope is a transport-neutral protocol message with transport-verified security context.
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

	Security  SecurityContext       `wire:"-"`
	Broadcast *BroadcastCertificate `wire:"-"`
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

// OpenEnvelope decodes a wire envelope and attaches transport-verified security context.
// It recomputes the transcript hash from the wire bytes and stores the provided
// SecurityContext and BroadcastCertificate. No protocol policy checks are performed.
func OpenEnvelope(raw []byte, security SecurityContext, broadcast *BroadcastCertificate) (Envelope, error) {
	return OpenEnvelopeWithLimits(raw, security, broadcast, defaultEnvelopeLimits())
}

// OpenEnvelopeWithLimits decodes a wire envelope with explicit limits and attaches
// transport-verified security context.
func OpenEnvelopeWithLimits(raw []byte, security SecurityContext, broadcast *BroadcastCertificate, limits EnvelopeLimits) (Envelope, error) {
	env, err := UnmarshalEnvelopeWithLimits(raw, limits)
	if err != nil {
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

// ValidateEnvelopePolicy checks delivery mode and confidentiality against a PolicySet.
// It is a lightweight complement for the test fallback path (when no EnvelopeGuard
// is set and the transport is unauthenticated). It does NOT check broadcast
// consistency or replay — those require guard infrastructure.
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
	// Both ConfidentialityRequired and ConfidentialityForbidden are always
	// checked regardless of the Authenticated flag. The guard path and this
	// fallback path must be consistent: a confidential-forbidden payload
	// arriving over a confidential channel is always a policy violation.
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

	return nil
}
