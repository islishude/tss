package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const (
	signAttemptRecordVersion       uint16 = 1
	signAttemptWireVersion         uint16 = 1
	signAttemptWireType                   = "cggmp21.secp256k1.sign-attempt"
	signAttemptIntentLabel                = "cggmp21-secp256k1-sign-attempt-intent-v1"
	signAttemptHashLabel                  = "cggmp21-secp256k1-sign-attempt-hash-v1"
	signAttemptSignerSetLabel             = "cggmp21-secp256k1-sign-attempt-signers-v1"
	signAttemptDeliveryPolicyLabel        = "cggmp21-secp256k1-sign-attempt-delivery-policy-v1"
)

// SignAttemptCommitStatus reports whether CommitSignAttempt created or reused
// the durable record.
type SignAttemptCommitStatus uint8

const (
	// SignAttemptCreated reports that CommitSignAttempt created a new attempt.
	SignAttemptCreated SignAttemptCommitStatus = iota
	// SignAttemptExistingSame reports that CommitSignAttempt found the same attempt.
	SignAttemptExistingSame
)

// SignAttemptCommit is the result of a successful durable attempt commit.
type SignAttemptCommit struct {
	Status SignAttemptCommitStatus
	Record SignAttemptRecord
}

// SignAttemptDeliveryPolicy snapshots the delivery policy that applies to the
// committed outbound signing envelope.
type SignAttemptDeliveryPolicy struct {
	Mode                 tss.DeliveryMode
	Confidentiality      tss.ConfidentialityPolicy
	BroadcastConsistency tss.BroadcastConsistencyPolicy
	Recipients           tss.PartySet
}

// Clone returns an independent copy of the delivery policy snapshot.
func (p SignAttemptDeliveryPolicy) Clone() SignAttemptDeliveryPolicy {
	return SignAttemptDeliveryPolicy{
		Mode:                 p.Mode,
		Confidentiality:      p.Confidentiality,
		BroadcastConsistency: p.BroadcastConsistency,
		Recipients:           slices.Clone(p.Recipients),
	}
}

// Equal reports whether p and other contain the same delivery policy snapshot.
func (p SignAttemptDeliveryPolicy) Equal(other SignAttemptDeliveryPolicy) bool {
	return p.Mode == other.Mode &&
		p.Confidentiality == other.Confidentiality &&
		p.BroadcastConsistency == other.BroadcastConsistency &&
		slices.Equal(p.Recipients, other.Recipients)
}

// SignAttemptDeliveryState tracks durable outbox delivery progress for one
// committed attempt.
type SignAttemptDeliveryState struct {
	Acks             []tss.BroadcastAck
	Certificate      *tss.BroadcastCertificate
	DeliveryComplete bool
}

// Clone returns an independent copy of the delivery state.
func (s SignAttemptDeliveryState) Clone() SignAttemptDeliveryState {
	return SignAttemptDeliveryState{
		Acks:             tss.CloneSlice(s.Acks),
		Certificate:      s.Certificate.Clone(),
		DeliveryComplete: s.DeliveryComplete,
	}
}

// Equal reports whether s and other contain the same durable delivery state.
func (s SignAttemptDeliveryState) Equal(other SignAttemptDeliveryState) bool {
	if s.DeliveryComplete != other.DeliveryComplete || len(s.Acks) != len(other.Acks) {
		return false
	}
	for i := range s.Acks {
		if !broadcastAckEqual(s.Acks[i], other.Acks[i]) {
			return false
		}
	}
	return broadcastCertificateEqual(s.Certificate, other.Certificate)
}

// SignAttemptDeliveryUpdate records one durable outbox delivery progress update.
type SignAttemptDeliveryUpdate struct {
	PresignID   []byte
	AttemptHash []byte
	Ack         *tss.BroadcastAck
	Certificate *tss.BroadcastCertificate
}

// SignAttemptBurn is a durable tombstone for a presign that must not be used.
type SignAttemptBurn struct {
	PresignID []byte
	Reason    string
}

// SignAttemptRecord is the canonical durable binding between one presign and
// one online signing intent. CanonicalBaseEnvelopeBytes contains a confidential
// partial signature and must be encrypted at rest.
type SignAttemptRecord struct {
	RecordVersion   uint16
	Protocol        tss.ProtocolID
	ProtocolVersion uint16
	PresignID       []byte
	AttemptHash     []byte
	IntentHash      []byte

	SessionID     tss.SessionID
	Party         tss.PartyID
	SignerSetHash []byte
	SignPlanHash  []byte

	ContextHash       []byte
	Digest            []byte
	DigestBindingHash []byte

	CanonicalBaseEnvelopeBytes []byte
	CanonicalBaseEnvelopeHash  []byte
	EnvelopeDigest             []byte
	PayloadHash                []byte

	DeliveryPolicy SignAttemptDeliveryPolicy
	DeliveryState  SignAttemptDeliveryState

	Completed           bool
	SignatureR          []byte
	SignatureS          []byte
	SignatureRecoveryID uint8
}

// Clone returns an independent copy of the sign-attempt record.
func (r SignAttemptRecord) Clone() SignAttemptRecord {
	return SignAttemptRecord{
		RecordVersion:              r.RecordVersion,
		Protocol:                   r.Protocol,
		ProtocolVersion:            r.ProtocolVersion,
		PresignID:                  slices.Clone(r.PresignID),
		AttemptHash:                slices.Clone(r.AttemptHash),
		IntentHash:                 slices.Clone(r.IntentHash),
		SessionID:                  r.SessionID,
		Party:                      r.Party,
		SignerSetHash:              slices.Clone(r.SignerSetHash),
		SignPlanHash:               slices.Clone(r.SignPlanHash),
		ContextHash:                slices.Clone(r.ContextHash),
		Digest:                     slices.Clone(r.Digest),
		DigestBindingHash:          slices.Clone(r.DigestBindingHash),
		CanonicalBaseEnvelopeBytes: slices.Clone(r.CanonicalBaseEnvelopeBytes),
		CanonicalBaseEnvelopeHash:  slices.Clone(r.CanonicalBaseEnvelopeHash),
		EnvelopeDigest:             slices.Clone(r.EnvelopeDigest),
		PayloadHash:                slices.Clone(r.PayloadHash),
		DeliveryPolicy:             r.DeliveryPolicy.Clone(),
		DeliveryState:              r.DeliveryState.Clone(),
		Completed:                  r.Completed,
		SignatureR:                 slices.Clone(r.SignatureR),
		SignatureS:                 slices.Clone(r.SignatureS),
		SignatureRecoveryID:        r.SignatureRecoveryID,
	}
}

// Equal reports whether r and other contain the same canonical durable record,
// including delivery and completion state. It compares fields directly and does
// not validate either record.
func (r SignAttemptRecord) Equal(other SignAttemptRecord) bool {
	return r.SameBaseAttempt(other) &&
		r.DeliveryState.Equal(other.DeliveryState) &&
		r.Completed == other.Completed &&
		bytes.Equal(r.SignatureR, other.SignatureR) &&
		bytes.Equal(r.SignatureS, other.SignatureS) &&
		r.SignatureRecoveryID == other.SignatureRecoveryID
}

// SameAttempt reports whether r and other identify the same committed attempt.
// It compares the presign, intent, and attempt hashes only.
func (r SignAttemptRecord) SameAttempt(other SignAttemptRecord) bool {
	return bytes.Equal(r.PresignID, other.PresignID) &&
		bytes.Equal(r.IntentHash, other.IntentHash) &&
		bytes.Equal(r.AttemptHash, other.AttemptHash)
}

// SameBaseAttempt reports whether r and other contain the same immutable base
// attempt, excluding delivery progress and completion state.
func (r SignAttemptRecord) SameBaseAttempt(other SignAttemptRecord) bool {
	return r.RecordVersion == other.RecordVersion &&
		r.Protocol == other.Protocol &&
		r.ProtocolVersion == other.ProtocolVersion &&
		r.SessionID == other.SessionID &&
		r.Party == other.Party &&
		bytes.Equal(r.PresignID, other.PresignID) &&
		bytes.Equal(r.AttemptHash, other.AttemptHash) &&
		bytes.Equal(r.IntentHash, other.IntentHash) &&
		bytes.Equal(r.SignerSetHash, other.SignerSetHash) &&
		bytes.Equal(r.SignPlanHash, other.SignPlanHash) &&
		bytes.Equal(r.ContextHash, other.ContextHash) &&
		bytes.Equal(r.Digest, other.Digest) &&
		bytes.Equal(r.DigestBindingHash, other.DigestBindingHash) &&
		bytes.Equal(r.CanonicalBaseEnvelopeBytes, other.CanonicalBaseEnvelopeBytes) &&
		bytes.Equal(r.CanonicalBaseEnvelopeHash, other.CanonicalBaseEnvelopeHash) &&
		bytes.Equal(r.EnvelopeDigest, other.EnvelopeDigest) &&
		bytes.Equal(r.PayloadHash, other.PayloadHash) &&
		r.DeliveryPolicy.Equal(other.DeliveryPolicy)
}

// MarshalJSON rejects JSON encoding of confidential sign-attempt records.
func (r SignAttemptRecord) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 sign attempt contains a confidential partial; use MarshalBinary")
}

// UnmarshalJSON rejects JSON decoding of confidential sign-attempt records.
func (r *SignAttemptRecord) UnmarshalJSON([]byte) error {
	return errors.New("cggmp21 secp256k1 sign attempt requires canonical binary decoding")
}

// MarshalBinary encodes the sign-attempt record using canonical TLV.
func (r SignAttemptRecord) MarshalBinary() ([]byte, error) {
	return r.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the sign-attempt record using explicit local
// resource limits.
func (r SignAttemptRecord) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return r.MarshalWireMessage(wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes and validates a canonical sign-attempt record.
func (r *SignAttemptRecord) UnmarshalBinary(in []byte) error {
	return r.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical sign-attempt record into the
// receiver using explicit local resource limits.
func (r *SignAttemptRecord) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if r == nil {
		return errors.New("nil sign attempt")
	}
	if len(in) == 0 {
		return errors.New("empty sign attempt")
	}
	if len(in) > limits.State.MaxSerializedSignAttemptBytes {
		return fmt.Errorf("sign attempt too large: %d > %d", len(in), limits.State.MaxSerializedSignAttemptBytes)
	}
	var decoded SignAttemptRecord
	if err := decoded.UnmarshalWireMessage(in,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	*r = decoded
	return nil
}

// WireType returns the canonical sign-attempt wire type.
func (SignAttemptRecord) WireType() string { return signAttemptWireType }

// WireVersion returns the sign-attempt wire version.
func (SignAttemptRecord) WireVersion() uint16 { return signAttemptWireVersion }

// MarshalWireMessage encodes SignAttemptRecord directly without an intermediate
// DTO. The field tags and values are the durable sign-attempt wire contract.
func (r SignAttemptRecord) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	resolved := wire.ResolveMarshalOptions(opts...)
	config, err := signAttemptCodecConfig(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(config.limits.fieldLimits()))
	}
	if err := validateSignAttemptRecordWithLimits(r, config.limits); err != nil {
		return nil, err
	}
	if err := checkSignAttemptWireBytes(r.CanonicalBaseEnvelopeBytes, config.envelopeBytes, "canonical base envelope"); err != nil {
		return nil, err
	}
	if err := checkSignAttemptWireBytes(r.SignatureR, config.scalarBytes, "signature r"); err != nil {
		return nil, err
	}
	if err := checkSignAttemptWireBytes(r.SignatureS, config.scalarBytes, "signature s"); err != nil {
		return nil, err
	}
	acks, err := marshalSignAttemptAcks(r.DeliveryState.Acks, opts...)
	if err != nil {
		return nil, err
	}
	var certificate []byte
	if r.DeliveryState.Certificate != nil {
		certificate, err = r.DeliveryState.Certificate.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode delivery certificate: %w", err)
		}
	}
	if err := checkSignAttemptWireBytes(certificate, config.envelopeBytes, "delivery certificate"); err != nil {
		return nil, err
	}
	recipients, err := wire.EncodeUint32ListChecked(r.DeliveryPolicy.Recipients)
	if err != nil {
		return nil, fmt.Errorf("encode delivery recipients: %w", err)
	}
	fields := []wire.Field{
		{Tag: 1, Value: wire.Uint16(r.RecordVersion)},
		{Tag: 2, Value: []byte(r.Protocol)},
		{Tag: 3, Value: wire.Uint16(r.ProtocolVersion)},
		{Tag: 4, Value: wire.NonNilBytes(bytes.Clone(r.PresignID))},
		{Tag: 5, Value: wire.NonNilBytes(bytes.Clone(r.AttemptHash))},
		{Tag: 6, Value: wire.NonNilBytes(bytes.Clone(r.IntentHash))},
		{Tag: 7, Value: r.SessionID[:]},
		{Tag: 8, Value: wire.Uint32(r.Party)},
		{Tag: 9, Value: wire.NonNilBytes(bytes.Clone(r.SignerSetHash))},
		{Tag: 10, Value: wire.NonNilBytes(bytes.Clone(r.SignPlanHash))},
		{Tag: 11, Value: wire.NonNilBytes(bytes.Clone(r.ContextHash))},
		{Tag: 12, Value: wire.NonNilBytes(bytes.Clone(r.Digest))},
		{Tag: 13, Value: wire.NonNilBytes(bytes.Clone(r.DigestBindingHash))},
		{Tag: 14, Value: wire.NonNilBytes(bytes.Clone(r.CanonicalBaseEnvelopeBytes))},
		{Tag: 15, Value: wire.NonNilBytes(bytes.Clone(r.CanonicalBaseEnvelopeHash))},
		{Tag: 16, Value: wire.NonNilBytes(bytes.Clone(r.EnvelopeDigest))},
		{Tag: 17, Value: wire.NonNilBytes(bytes.Clone(r.PayloadHash))},
		{Tag: 18, Value: signAttemptUint8(uint8(r.DeliveryPolicy.Mode))},
		{Tag: 19, Value: signAttemptUint8(uint8(r.DeliveryPolicy.Confidentiality))},
		{Tag: 20, Value: signAttemptUint8(uint8(r.DeliveryPolicy.BroadcastConsistency))},
		{Tag: 21, Value: recipients},
		{Tag: 22, Value: acks},
		{Tag: 23, Value: wire.NonNilBytes(certificate)},
		{Tag: 24, Value: wire.Bool(r.DeliveryState.DeliveryComplete)},
		{Tag: 25, Value: wire.Bool(r.Completed)},
		{Tag: 26, Value: wire.NonNilBytes(bytes.Clone(r.SignatureR))},
		{Tag: 27, Value: wire.NonNilBytes(bytes.Clone(r.SignatureS))},
		{Tag: 28, Value: signAttemptUint8(r.SignatureRecoveryID)},
	}
	return wire.MarshalMessageBody(r, fields)
}

// UnmarshalWireMessage decodes SignAttemptRecord directly without an
// intermediate DTO and rejects any non-canonical field set.
func (r *SignAttemptRecord) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if r == nil {
		return errors.New("nil sign attempt")
	}
	resolved := wire.ResolveUnmarshalOptions(opts...)
	config, err := signAttemptCodecConfig(resolved.FieldLimits)
	if err != nil {
		return err
	}
	config.limits.State.MaxSerializedSignAttemptBytes = resolved.FrameLimits.MaxTotalBytes
	config.limits.TLV.MaxFields = resolved.FrameLimits.MaxFields
	config.limits.TLV.MaxFieldBytes = resolved.FrameLimits.MaxFieldBytes
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimits(config.limits.fieldLimits()))
	}
	fields, err := wire.UnmarshalMessageBody(in, r, opts...)
	if err != nil {
		return err
	}
	if err := requireSignAttemptRecordTags(fields); err != nil {
		return err
	}
	recordVersion, err := wire.DecodeUint16(fields[0].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt record version: %w", err)
	}
	protocol, err := decodeSignAttemptString(fields[1].Value, "protocol")
	if err != nil {
		return err
	}
	protocolVersion, err := wire.DecodeUint16(fields[2].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt protocol version: %w", err)
	}
	sessionID, err := tss.SessionIDFromBytes(fields[6].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt session id: %w", err)
	}
	party, err := wire.DecodeUint32(fields[7].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt party: %w", err)
	}
	deliveryMode, err := decodeSignAttemptUint8(fields[17].Value, "delivery mode")
	if err != nil {
		return err
	}
	confidentiality, err := decodeSignAttemptUint8(fields[18].Value, "confidentiality")
	if err != nil {
		return err
	}
	broadcastConsistency, err := decodeSignAttemptUint8(fields[19].Value, "broadcast consistency")
	if err != nil {
		return err
	}
	recipients, err := wire.DecodeUint32List[tss.PartyID](fields[20].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt recipients: %w", err)
	}
	acks, err := unmarshalSignAttemptAcks(fields[21].Value, resolved.FrameLimits, opts...)
	if err != nil {
		return err
	}
	if err := checkSignAttemptWireBytes(fields[13].Value, config.envelopeBytes, "canonical base envelope"); err != nil {
		return err
	}
	if err := checkSignAttemptWireBytes(fields[22].Value, config.envelopeBytes, "delivery certificate"); err != nil {
		return err
	}
	if err := checkSignAttemptWireBytes(fields[25].Value, config.scalarBytes, "signature r"); err != nil {
		return err
	}
	if err := checkSignAttemptWireBytes(fields[26].Value, config.scalarBytes, "signature s"); err != nil {
		return err
	}
	var certificate *tss.BroadcastCertificate
	if len(fields[22].Value) > 0 {
		certificate, err = tss.DecodeBinary[tss.BroadcastCertificate](fields[22].Value)
		if err != nil {
			return fmt.Errorf("invalid delivery certificate: %w", err)
		}
	}
	deliveryComplete, err := wire.DecodeBool(fields[23].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt delivery complete: %w", err)
	}
	completed, err := wire.DecodeBool(fields[24].Value)
	if err != nil {
		return fmt.Errorf("invalid sign attempt completed: %w", err)
	}
	recoveryID, err := decodeSignAttemptUint8(fields[27].Value, "signature recovery id")
	if err != nil {
		return err
	}
	record := SignAttemptRecord{
		RecordVersion:              recordVersion,
		Protocol:                   tss.ProtocolID(protocol),
		ProtocolVersion:            protocolVersion,
		PresignID:                  bytes.Clone(fields[3].Value),
		AttemptHash:                bytes.Clone(fields[4].Value),
		IntentHash:                 bytes.Clone(fields[5].Value),
		SessionID:                  sessionID,
		Party:                      party,
		SignerSetHash:              bytes.Clone(fields[8].Value),
		SignPlanHash:               bytes.Clone(fields[9].Value),
		ContextHash:                bytes.Clone(fields[10].Value),
		Digest:                     bytes.Clone(fields[11].Value),
		DigestBindingHash:          bytes.Clone(fields[12].Value),
		CanonicalBaseEnvelopeBytes: bytes.Clone(fields[13].Value),
		CanonicalBaseEnvelopeHash:  bytes.Clone(fields[14].Value),
		EnvelopeDigest:             bytes.Clone(fields[15].Value),
		PayloadHash:                bytes.Clone(fields[16].Value),
		DeliveryPolicy: SignAttemptDeliveryPolicy{
			Mode:                 tss.DeliveryMode(deliveryMode),
			Confidentiality:      tss.ConfidentialityPolicy(confidentiality),
			BroadcastConsistency: tss.BroadcastConsistencyPolicy(broadcastConsistency),
			Recipients:           recipients,
		},
		DeliveryState: SignAttemptDeliveryState{
			Acks:             acks,
			Certificate:      certificate,
			DeliveryComplete: deliveryComplete,
		},
		Completed:           completed,
		SignatureR:          bytes.Clone(fields[25].Value),
		SignatureS:          bytes.Clone(fields[26].Value),
		SignatureRecoveryID: recoveryID,
	}
	if err := validateSignAttemptRecordWithLimits(record, config.limits); err != nil {
		return err
	}
	*r = record
	return nil
}

// Validate checks the sign-attempt record against default local limits.
func (r SignAttemptRecord) Validate() error {
	return validateSignAttemptRecord(r)
}

// ValidateWithLimits checks the sign-attempt record against explicit local
// resource limits.
func (r SignAttemptRecord) ValidateWithLimits(limits Limits) error {
	return validateSignAttemptRecordWithLimits(r, limits)
}

// SignAttemptResult supplies the final signature for an existing durable attempt.
type SignAttemptResult struct {
	PresignID   []byte
	AttemptHash []byte
	Signature   Signature
}

func (r SignAttemptResult) validate() error {
	if len(r.PresignID) != sha256.Size {
		return errors.New("invalid result presign ID")
	}
	if len(r.AttemptHash) != sha256.Size {
		return errors.New("invalid result attempt hash")
	}
	if _, err := scalarBytesStrict(r.Signature.R); err != nil {
		return fmt.Errorf("invalid result signature r: %w", err)
	}
	s, err := scalarStrict(r.Signature.S)
	if err != nil {
		return fmt.Errorf("invalid result signature s: %w", err)
	}
	if !secp.IsLowS(s) {
		return errors.New("invalid result signature s: high-S signatures are not canonical")
	}
	if r.Signature.RecoveryID > 3 {
		return errors.New("invalid result signature recovery id")
	}
	return nil
}

type signAttemptCodecOptions struct {
	limits        Limits
	envelopeBytes int
	scalarBytes   int
}

func signAttemptCodecConfig(fieldLimits wire.FieldLimits) (signAttemptCodecOptions, error) {
	limits := DefaultLimits()
	effective := fieldLimits
	if effective == nil {
		effective = limits.fieldLimits()
	}
	envelopeBytes, err := signAttemptRequiredFieldLimit(effective, "envelope")
	if err != nil {
		return signAttemptCodecOptions{}, err
	}
	scalarBytes, err := signAttemptRequiredFieldLimit(effective, "scalar")
	if err != nil {
		return signAttemptCodecOptions{}, err
	}
	limits.Curve.MaxScalarBytes = scalarBytes
	if value, ok := effective["signprep_partial_signature"]; ok {
		if value <= 0 {
			return signAttemptCodecOptions{}, fmt.Errorf("wire: field limit %q for sign attempt record must be positive", "signprep_partial_signature")
		}
		limits.SignPrep.MaxSignPartialPayloadBytes = value
	}
	if value, ok := effective["broadcast_signature"]; ok && value <= 0 {
		return signAttemptCodecOptions{}, fmt.Errorf("wire: field limit %q for sign attempt record must be positive", "broadcast_signature")
	}
	return signAttemptCodecOptions{
		limits:        limits,
		envelopeBytes: envelopeBytes,
		scalarBytes:   scalarBytes,
	}, nil
}

func signAttemptRequiredFieldLimit(fieldLimits wire.FieldLimits, name string) (int, error) {
	value, ok := fieldLimits[name]
	if !ok {
		return 0, fmt.Errorf("wire: missing field limit %q for sign attempt record", name)
	}
	if value <= 0 {
		return 0, fmt.Errorf("wire: field limit %q for sign attempt record must be positive", name)
	}
	return value, nil
}

func requireSignAttemptRecordTags(fields []wire.Field) error {
	if len(fields) != 28 {
		return fmt.Errorf("sign attempt record field count %d != 28", len(fields))
	}
	for i, field := range fields {
		want := uint16(i + 1)
		if field.Tag != want {
			return fmt.Errorf("sign attempt record tag %d at index %d, want %d", field.Tag, i, want)
		}
	}
	return nil
}

func signAttemptUint8(v uint8) []byte {
	return []byte{v}
}

func decodeSignAttemptUint8(raw []byte, name string) (uint8, error) {
	if len(raw) != 1 {
		return 0, fmt.Errorf("invalid sign attempt %s: u8: got %d bytes, want 1", name, len(raw))
	}
	return raw[0], nil
}

func decodeSignAttemptString(raw []byte, name string) (string, error) {
	if !utf8.Valid(raw) {
		return "", fmt.Errorf("invalid sign attempt %s: string is not valid UTF-8", name)
	}
	return string(raw), nil
}

func checkSignAttemptWireBytes(raw []byte, maxBytes int, name string) error {
	if maxBytes > 0 && len(raw) > maxBytes {
		return fmt.Errorf("sign attempt %s too large: %d > %d", name, len(raw), maxBytes)
	}
	return nil
}

func marshalSignAttemptAcks(acks []tss.BroadcastAck, opts ...wire.MarshalOption) ([]byte, error) {
	if uint64(len(acks)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("delivery ack count %d exceeds uint32", len(acks))
	}
	out := wire.Uint32(uint32(len(acks)))
	for i, ack := range acks {
		record, err := wire.MarshalRecordValue(ack, opts...)
		if err != nil {
			return nil, fmt.Errorf("delivery ack %d: %w", i, err)
		}
		out, err = wire.AppendBytesChecked(out, record)
		if err != nil {
			return nil, fmt.Errorf("delivery ack %d: %w", i, err)
		}
	}
	return out, nil
}

func unmarshalSignAttemptAcks(raw []byte, frameLimits wire.FrameLimits, opts ...wire.UnmarshalOption) ([]tss.BroadcastAck, error) {
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid delivery ack count: %w", err)
	}
	if uint64(count) > 65535 {
		return nil, fmt.Errorf("delivery ack count %d exceeds global limit", count)
	}
	if uint64(count)*4 > uint64(len(raw)-offset) {
		return nil, errors.New("invalid delivery ack list length")
	}
	out := make([]tss.BroadcastAck, 0, int(count))
	for i := range int(count) {
		record, next, err := wire.ReadBytesWithLimit(raw, offset, frameLimits.MaxFieldBytes)
		if err != nil {
			return nil, fmt.Errorf("delivery ack %d: %w", i, err)
		}
		offset = next
		var ack tss.BroadcastAck
		if err := wire.UnmarshalRecordValue(record, &ack, opts...); err != nil {
			return nil, fmt.Errorf("delivery ack %d: %w", i, err)
		}
		out = append(out, ack.Clone())
	}
	if offset != len(raw) {
		return nil, errors.New("trailing delivery ack data")
	}
	return out, nil
}

func validateSignAttemptRecord(r SignAttemptRecord) error {
	return validateSignAttemptRecordWithLimits(r, DefaultLimits())
}

func validateSignAttemptRecordWithLimits(r SignAttemptRecord, limits Limits) error {
	if r.RecordVersion != signAttemptRecordVersion {
		return fmt.Errorf("%w: unexpected sign attempt record version %d", ErrSignAttemptCorrupt, r.RecordVersion)
	}
	if r.Protocol != tss.ProtocolCGGMP21Secp256k1 {
		return fmt.Errorf("%w: unexpected protocol %q", ErrSignAttemptCorrupt, r.Protocol)
	}
	if r.ProtocolVersion != tss.ProtocolVersion {
		return fmt.Errorf("%w: unexpected protocol version %d", ErrSignAttemptCorrupt, r.ProtocolVersion)
	}
	if len(r.PresignID) != sha256.Size || len(r.AttemptHash) != sha256.Size ||
		len(r.IntentHash) != sha256.Size || len(r.SignerSetHash) != sha256.Size ||
		len(r.SignPlanHash) != sha256.Size ||
		len(r.ContextHash) != sha256.Size || len(r.Digest) != sha256.Size ||
		len(r.DigestBindingHash) != sha256.Size || len(r.CanonicalBaseEnvelopeHash) != sha256.Size ||
		len(r.EnvelopeDigest) != sha256.Size || len(r.PayloadHash) != sha256.Size {
		return fmt.Errorf("%w: invalid fixed-length field", ErrSignAttemptCorrupt)
	}
	if !r.SessionID.Valid() || r.Party == tss.BroadcastPartyId {
		return fmt.Errorf("%w: invalid session or party", ErrSignAttemptCorrupt)
	}
	if len(r.CanonicalBaseEnvelopeBytes) == 0 || len(r.CanonicalBaseEnvelopeBytes) > tss.DefaultMaxEnvelopeBytes {
		return fmt.Errorf("%w: invalid envelope length", ErrSignAttemptCorrupt)
	}
	env, err := decodeSignAttemptEnvelopeWithLimits(r.CanonicalBaseEnvelopeBytes, limits)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	envelopeHash := sha256.Sum256(r.CanonicalBaseEnvelopeBytes)
	if !bytes.Equal(r.CanonicalBaseEnvelopeHash, envelopeHash[:]) {
		return fmt.Errorf("%w: envelope hash mismatch", ErrSignAttemptCorrupt)
	}
	payloadHash := tss.PayloadHashFromEnvelope(env)
	if !bytes.Equal(r.PayloadHash, payloadHash[:]) {
		return fmt.Errorf("%w: payload hash mismatch", ErrSignAttemptCorrupt)
	}
	envelopeDigest := env.Digest()
	if !bytes.Equal(r.EnvelopeDigest, envelopeDigest[:]) {
		return fmt.Errorf("%w: envelope digest mismatch", ErrSignAttemptCorrupt)
	}
	if env.Protocol != r.Protocol || env.SessionID != r.SessionID ||
		env.Round != signStartRound || env.From != r.Party || env.To != tss.BroadcastPartyId || env.PayloadType != payloadSignPartial {
		return fmt.Errorf("%w: envelope binding mismatch", ErrSignAttemptCorrupt)
	}
	payload, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](env.Payload, limits)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	expectedDigestBinding := digestHash(r.Digest, r.ContextHash)
	if !bytes.Equal(r.DigestBindingHash, expectedDigestBinding) || !bytes.Equal(payload.DigestHash, r.DigestBindingHash) {
		return fmt.Errorf("%w: digest binding hash mismatch", ErrSignAttemptCorrupt)
	}
	if !bytes.Equal(payload.PresignContext, r.ContextHash) {
		return fmt.Errorf("%w: payload context hash mismatch", ErrSignAttemptCorrupt)
	}
	if !bytes.Equal(payload.PlanHash, r.SignPlanHash) {
		return fmt.Errorf("%w: payload sign plan hash mismatch", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptDeliveryPolicy(r, env); err != nil {
		return err
	}
	if err := validateSignAttemptDeliveryState(r, env); err != nil {
		return err
	}
	expectedIntent := signAttemptIntentHash(r)
	if !bytes.Equal(r.IntentHash, expectedIntent) {
		return fmt.Errorf("%w: intent hash mismatch", ErrSignAttemptCorrupt)
	}
	expectedAttempt := signAttemptHash(r)
	if !bytes.Equal(r.AttemptHash, expectedAttempt) {
		return fmt.Errorf("%w: attempt hash mismatch", ErrSignAttemptCorrupt)
	}
	if r.Completed {
		if _, err := scalarBytesStrict(r.SignatureR); err != nil {
			return fmt.Errorf("%w: invalid signature r", ErrSignAttemptCorrupt)
		}
		s, err := scalarStrict(r.SignatureS)
		if err != nil {
			return fmt.Errorf("%w: invalid signature s", ErrSignAttemptCorrupt)
		}
		if !secp.IsLowS(s) {
			return fmt.Errorf("%w: high-S signature is not canonical", ErrSignAttemptCorrupt)
		}
		if r.SignatureRecoveryID > 3 {
			return fmt.Errorf("%w: invalid signature recovery id", ErrSignAttemptCorrupt)
		}
	} else if len(r.SignatureR) != 0 || len(r.SignatureS) != 0 || r.SignatureRecoveryID != 0 {
		return fmt.Errorf("%w: incomplete record contains signature", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateSignAttemptCandidate(r SignAttemptRecord) error {
	if err := validateSignAttemptRecord(r); err != nil {
		return err
	}
	if r.Completed {
		return errors.New("sign attempt commit candidate is already completed")
	}
	if len(r.DeliveryState.Acks) != 0 || r.DeliveryState.Certificate != nil || r.DeliveryState.DeliveryComplete {
		return errors.New("sign attempt commit candidate contains delivery state")
	}
	return nil
}

func validateSignAttemptDeliveryPolicy(r SignAttemptRecord, env tss.Envelope) error {
	policy, err := CGGMP21Policies().Match(r.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return fmt.Errorf("%w: sign attempt delivery policy lookup: %w", ErrSignAttemptCorrupt, err)
	}
	if r.DeliveryPolicy.Mode != policy.Mode ||
		r.DeliveryPolicy.Confidentiality != policy.Confidentiality ||
		r.DeliveryPolicy.BroadcastConsistency != policy.BroadcastConsistency {
		return fmt.Errorf("%w: delivery policy snapshot mismatch", ErrSignAttemptCorrupt)
	}
	if len(r.DeliveryPolicy.Recipients) == 0 {
		return fmt.Errorf("%w: empty delivery recipients", ErrSignAttemptCorrupt)
	}
	if err := wire.ValidateStrictSortedIDs(r.DeliveryPolicy.Recipients); err != nil {
		return fmt.Errorf("%w: invalid delivery recipients: %w", ErrSignAttemptCorrupt, err)
	}
	if !bytes.Equal(r.SignerSetHash, signAttemptSignerSetHash(r.DeliveryPolicy.Recipients)) {
		return fmt.Errorf("%w: delivery recipients do not match signer set", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateSignAttemptDeliveryState(r SignAttemptRecord, env tss.Envelope) error {
	recipients := r.DeliveryPolicy.Recipients
	seen := make(map[tss.PartyID]struct{}, len(r.DeliveryState.Acks))
	order := signAttemptRecipientOrder(r.DeliveryPolicy.Recipients)
	prev := -1
	for _, ack := range r.DeliveryState.Acks {
		if err := validateSignAttemptDeliveryAck(ack, env, recipients); err != nil {
			return err
		}
		index := order[ack.Party]
		if index <= prev {
			return fmt.Errorf("%w: non-canonical delivery ack order", ErrSignAttemptCorrupt)
		}
		prev = index
		if _, ok := seen[ack.Party]; ok {
			return fmt.Errorf("%w: duplicate delivery ack", ErrSignAttemptCorrupt)
		}
		seen[ack.Party] = struct{}{}
	}
	if r.DeliveryState.Certificate != nil {
		if err := r.DeliveryState.Certificate.VerifyStructure(env, recipients); err != nil {
			return fmt.Errorf("%w: delivery certificate: %w", ErrSignAttemptCorrupt, err)
		}
		if err := wire.ValidateStrictSortedIDs(r.DeliveryState.Certificate.Recipients); err != nil ||
			!slices.Equal(r.DeliveryState.Certificate.Recipients, r.DeliveryPolicy.Recipients) {
			return fmt.Errorf("%w: non-canonical delivery certificate recipients: %w", ErrSignAttemptCorrupt, err)
		}
		prev := -1
		for _, ack := range r.DeliveryState.Certificate.Acks {
			index := order[ack.Party]
			if index <= prev {
				return fmt.Errorf("%w: non-canonical delivery certificate ack order", ErrSignAttemptCorrupt)
			}
			prev = index
		}
		if _, err := r.DeliveryState.Certificate.MarshalBinary(); err != nil {
			return fmt.Errorf("%w: delivery certificate encoding: %w", ErrSignAttemptCorrupt, err)
		}
	}
	if r.DeliveryState.DeliveryComplete {
		if r.DeliveryState.Certificate == nil {
			return fmt.Errorf("%w: complete delivery without certificate", ErrSignAttemptCorrupt)
		}
		if len(r.DeliveryState.Acks) != len(r.DeliveryPolicy.Recipients) {
			return fmt.Errorf("%w: complete delivery without all acks", ErrSignAttemptCorrupt)
		}
	}
	return nil
}

func validateSignAttemptDeliveryAck(ack tss.BroadcastAck, env tss.Envelope, recipients tss.PartySet) error {
	if !recipients.Contains(ack.Party) {
		return fmt.Errorf("%w: delivery ack from non-recipient", ErrSignAttemptCorrupt)
	}
	if ack.PayloadHash != tss.PayloadHashFromEnvelope(env) || ack.EnvelopeDigest != env.Digest() {
		return fmt.Errorf("%w: delivery ack binding mismatch", ErrSignAttemptCorrupt)
	}
	return nil
}

func applySignAttemptDeliveryUpdate(record SignAttemptRecord, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if err := validateSignAttemptRecord(record); err != nil {
		return SignAttemptRecord{}, err
	}
	if len(update.PresignID) != sha256.Size || len(update.AttemptHash) != sha256.Size {
		return SignAttemptRecord{}, errors.New("invalid delivery update identity")
	}
	if !bytes.Equal(update.PresignID, record.PresignID) || !bytes.Equal(update.AttemptHash, record.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if update.Ack == nil && update.Certificate == nil {
		return record.Clone(), nil
	}
	env, err := decodeSignAttemptEnvelope(record.CanonicalBaseEnvelopeBytes)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	recipients := record.DeliveryPolicy.Recipients
	updated := record.Clone()
	if update.Ack != nil {
		if err := addSignAttemptDeliveryAck(&updated, update.Ack.Clone(), env, recipients); err != nil {
			return SignAttemptRecord{}, err
		}
	}
	if update.Certificate != nil {
		cert := update.Certificate.Clone()
		if err := cert.VerifyStructure(env, recipients); err != nil {
			return SignAttemptRecord{}, fmt.Errorf("%w: delivery certificate: %w", ErrSignAttemptCorrupt, err)
		}
		cert.Recipients = updated.DeliveryPolicy.Recipients.Clone()
		orderSignAttemptCertificateAcks(cert, updated.DeliveryPolicy.Recipients)
		if _, err := cert.MarshalBinary(); err != nil {
			return SignAttemptRecord{}, fmt.Errorf("%w: delivery certificate encoding: %w", ErrSignAttemptCorrupt, err)
		}
		for _, ack := range cert.Acks {
			if err := addSignAttemptDeliveryAck(&updated, ack.Clone(), env, recipients); err != nil {
				return SignAttemptRecord{}, err
			}
		}
		updated.DeliveryState.Certificate = cert
		updated.DeliveryState.DeliveryComplete = true
	}
	orderSignAttemptDeliveryAcks(&updated)
	if err := validateSignAttemptRecord(updated); err != nil {
		return SignAttemptRecord{}, err
	}
	return updated, nil
}

func addSignAttemptDeliveryAck(record *SignAttemptRecord, ack tss.BroadcastAck, env tss.Envelope, recipients tss.PartySet) error {
	if err := validateSignAttemptDeliveryAck(ack, env, recipients); err != nil {
		return err
	}
	for _, existing := range record.DeliveryState.Acks {
		if existing.Party == ack.Party {
			return nil
		}
	}
	record.DeliveryState.Acks = append(record.DeliveryState.Acks, ack.Clone())
	return nil
}

func orderSignAttemptDeliveryAcks(record *SignAttemptRecord) {
	if len(record.DeliveryState.Acks) <= 1 {
		return
	}
	order := signAttemptRecipientOrder(record.DeliveryPolicy.Recipients)
	slices.SortStableFunc(record.DeliveryState.Acks, func(a, b tss.BroadcastAck) int {
		return order[a.Party] - order[b.Party]
	})
}

func orderSignAttemptCertificateAcks(cert *tss.BroadcastCertificate, recipients tss.PartySet) {
	if cert == nil || len(cert.Acks) <= 1 {
		return
	}
	order := signAttemptRecipientOrder(recipients)
	slices.SortStableFunc(cert.Acks, func(a, b tss.BroadcastAck) int {
		return order[a.Party] - order[b.Party]
	})
}

func signAttemptRecipientOrder(recipients tss.PartySet) map[tss.PartyID]int {
	order := make(map[tss.PartyID]int, len(recipients))
	for i, id := range recipients {
		order[id] = i
	}
	return order
}

func scalarBytesStrict(in []byte) ([]byte, error) {
	if _, err := scalarStrict(in); err != nil {
		return nil, err
	}
	return in, nil
}

func scalarStrict(in []byte) (secp.Scalar, error) {
	if len(in) != secp.ScalarSize {
		return secp.Scalar{}, errors.New("scalar must be 32 bytes")
	}
	return secp.ScalarFromBytes(in)
}

func decodeSignAttemptEnvelope(raw []byte) (tss.Envelope, error) {
	return decodeSignAttemptEnvelopeWithLimits(raw, DefaultLimits())
}

func decodeSignAttemptEnvelopeWithLimits(raw []byte, limits Limits) (tss.Envelope, error) {
	var env tss.Envelope
	if err := env.UnmarshalBinary(raw); err != nil {
		return tss.Envelope{}, err
	}
	canonical, err := env.MarshalBinary()
	if err != nil {
		return tss.Envelope{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return tss.Envelope{}, errors.New("non-canonical envelope")
	}
	if _, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](env.Payload, limits); err != nil {
		return tss.Envelope{}, err
	}
	return env, nil
}

func signAttemptIntentHash(r SignAttemptRecord) []byte {
	t := transcript.New(signAttemptIntentLabel)
	t.AppendUint16("record_version", r.RecordVersion)
	t.AppendString("protocol", string(r.Protocol))
	t.AppendUint16("protocol_version", r.ProtocolVersion)
	t.AppendBytes("presign_id", r.PresignID)
	t.AppendBytes("session_id", r.SessionID[:])
	t.AppendUint32("party", r.Party)
	t.AppendBytes("signer_set_hash", r.SignerSetHash)
	t.AppendBytes("sign_plan_hash", r.SignPlanHash)
	t.AppendBytes("context_hash", r.ContextHash)
	t.AppendBytes("digest", r.Digest)
	t.AppendBytes("digest_binding_hash", r.DigestBindingHash)
	return t.Sum()
}

func signAttemptHash(r SignAttemptRecord) []byte {
	t := transcript.New(signAttemptHashLabel)
	t.AppendBytes("intent_hash", r.IntentHash)
	t.AppendBytes("canonical_base_envelope_hash", r.CanonicalBaseEnvelopeHash)
	t.AppendBytes("envelope_digest", r.EnvelopeDigest)
	t.AppendBytes("payload_hash", r.PayloadHash)
	t.AppendBytes("delivery_policy_hash", signAttemptDeliveryPolicyHash(r.DeliveryPolicy))
	return t.Sum()
}

func signAttemptDeliveryPolicyHash(p SignAttemptDeliveryPolicy) []byte {
	t := transcript.New(signAttemptDeliveryPolicyLabel)
	t.AppendUint8("mode", uint8(p.Mode))
	t.AppendUint8("confidentiality", uint8(p.Confidentiality))
	t.AppendUint8("broadcast_consistency", uint8(p.BroadcastConsistency))
	t.AppendUint32List("recipients", p.Recipients)
	return t.Sum()
}

func signAttemptSignerSetHash(signers tss.PartySet) []byte {
	return wireutil.PartySetHash(signers, signAttemptSignerSetLabel)
}

func broadcastAckEqual(a, b tss.BroadcastAck) bool {
	return a.Party == b.Party &&
		a.PayloadHash == b.PayloadHash &&
		a.EnvelopeDigest == b.EnvelopeDigest &&
		bytes.Equal(a.Signature, b.Signature)
}

func broadcastCertificateEqual(a, b *tss.BroadcastCertificate) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Protocol != b.Protocol ||
		a.SessionID != b.SessionID ||
		a.Round != b.Round ||
		a.From != b.From ||
		a.PayloadType != b.PayloadType ||
		a.PayloadHash != b.PayloadHash ||
		a.EnvelopeDigest != b.EnvelopeDigest ||
		!slices.Equal(a.Recipients, b.Recipients) ||
		len(a.Acks) != len(b.Acks) {
		return false
	}
	for i := range a.Acks {
		if !broadcastAckEqual(a.Acks[i], b.Acks[i]) {
			return false
		}
	}
	return true
}
