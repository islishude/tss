package tss

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

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
	// Verify exact field set and order in a single pass — avoids nine
	// individual linear scans through the field list.
	if err := wire.RequireExactTags(fields,
		envelopeFieldProtocol,
		envelopeFieldVersion,
		envelopeFieldSessionID,
		envelopeFieldRound,
		envelopeFieldFrom,
		envelopeFieldTo,
		envelopeFieldPayloadType,
		envelopeFieldPayload,
		envelopeFieldTranscriptHash,
	); err != nil {
		return err
	}
	protocol := fields[0].Value
	if len(protocol) == 0 {
		return errors.New("envelope protocol is empty")
	}
	if len(protocol) > limits.MaxProtocolNameBytes {
		return fmt.Errorf("envelope protocol name too long: %d > %d", len(protocol), limits.MaxProtocolNameBytes)
	}
	envVersion, err := wire.DecodeUint16(fields[1].Value)
	if err != nil {
		return fmt.Errorf("invalid envelope version field: %w", err)
	}
	if envVersion != Version {
		return fmt.Errorf("unexpected envelope version %d", envVersion)
	}
	session, err := SessionIDFromBytes(fields[2].Value)
	if err != nil {
		return err
	}
	round := fields[3].Value
	if len(round) != 1 {
		return errors.New("invalid envelope round")
	}
	from, err := wire.DecodeUint32(fields[4].Value)
	if err != nil {
		return fmt.Errorf("invalid envelope sender: %w", err)
	}
	to, err := wire.DecodeUint32(fields[5].Value)
	if err != nil {
		return fmt.Errorf("invalid envelope recipient: %w", err)
	}
	payloadType := fields[6].Value
	if len(payloadType) == 0 {
		return errors.New("envelope payload type is empty")
	}
	if len(payloadType) > limits.MaxPayloadTypeBytes {
		return fmt.Errorf("envelope payload type too long: %d > %d", len(payloadType), limits.MaxPayloadTypeBytes)
	}
	payload := fields[7].Value
	if len(payload) > limits.MaxEnvelopePayloadBytes {
		return fmt.Errorf("envelope payload too large: %d > %d", len(payload), limits.MaxEnvelopePayloadBytes)
	}
	transcript := fields[8].Value
	if len(transcript) != sha256.Size {
		return errors.New("invalid envelope transcript hash")
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
		TranscriptHash: [32]byte(transcript),
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
