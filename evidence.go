package tss

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss/internal/wire"
)

// EvidenceKind names the protocol failure class captured in blame evidence.
type EvidenceKind string

const (
	// EvidenceKindKeygenCommitment marks an invalid keygen public commitment.
	EvidenceKindKeygenCommitment EvidenceKind = "keygen_commitment"
	// EvidenceKindKeygenPaillier marks invalid Paillier key material or proof.
	EvidenceKindKeygenPaillier EvidenceKind = "keygen_paillier"
	// EvidenceKindKeygenShare marks a DKG share that does not match commitments.
	EvidenceKindKeygenShare EvidenceKind = "keygen_share"
	// EvidenceKindRefreshShare marks a proactive refresh share that does not match commitments.
	EvidenceKindRefreshShare EvidenceKind = "refresh_share"
	// EvidenceKindReshareShare marks a CGGMP21 reshare share that does not match commitments.
	EvidenceKindReshareShare EvidenceKind = "reshare_share"
	// EvidenceKindPresignRound1 marks invalid presign nonce commitment material.
	EvidenceKindPresignRound1 EvidenceKind = "presign_round1"
	// EvidenceKindPresignRound2 marks invalid pairwise MtA response material.
	EvidenceKindPresignRound2 EvidenceKind = "presign_round2"
	// EvidenceKindPresignRound3 marks invalid presign delta broadcast material.
	EvidenceKindPresignRound3 EvidenceKind = "presign_round3"
	// EvidenceKindSignPartial marks invalid online signing partial material.
	EvidenceKindSignPartial EvidenceKind = "sign_partial"
	// EvidenceKindAggregateSign marks a final aggregate signature verification failure.
	EvidenceKindAggregateSign EvidenceKind = "aggregate_signature"
	// EvidenceKindFrostKeygenShare marks an invalid FROST DKG share.
	EvidenceKindFrostKeygenShare EvidenceKind = "frost_keygen_share"
	// EvidenceKindFrostReshareShare marks an invalid FROST reshare share.
	EvidenceKindFrostReshareShare EvidenceKind = "frost_reshare_share"
	// EvidenceKindFrostPartialSignature marks an invalid FROST partial signature.
	EvidenceKindFrostPartialSignature EvidenceKind = "frost_partial_signature"
	// EvidenceKindFrostAggregateSignature marks a failed FROST aggregate Ed25519 signature.
	EvidenceKindFrostAggregateSignature EvidenceKind = "frost_aggregate_signature"
)

// blameWireType is the TLV type identifier for blame evidence records.
const blameWireType = "tss.blame"

const (
	blameFieldVersion        uint16 = 1
	blameFieldProtocol       uint16 = 2
	blameFieldSessionID      uint16 = 3
	blameFieldRound          uint16 = 4
	blameFieldFrom           uint16 = 5
	blameFieldTo             uint16 = 6
	blameFieldPayloadType    uint16 = 7
	blameFieldPayloadHash    uint16 = 8
	blameFieldTranscriptHash uint16 = 9
	blameFieldKind           uint16 = 10
	blameFieldReason         uint16 = 11
	blameFieldPublicInputs   uint16 = 12
)

// EvidenceField carries one public input or public-input hash for blame evidence.
type EvidenceField struct {
	Key   string
	Value []byte
}

// Clone returns a deep copy of an evidence field.
func (f EvidenceField) Clone() EvidenceField {
	return EvidenceField{
		Key:   f.Key,
		Value: slices.Clone(f.Value),
	}
}

// BlameEvidence is intentionally public-only. Confidential protocol messages
// should be represented by hashes or other public inputs, not by plaintext.
type BlameEvidence struct {
	Version        uint16
	Protocol       ProtocolID
	SessionID      SessionID
	Round          uint8
	From           PartyID
	To             PartyID
	PayloadType    PayloadType
	PayloadHash    []byte
	TranscriptHash []byte
	Kind           EvidenceKind
	Reason         string
	PublicInputs   []EvidenceField
}

// NewBlameEvidence builds a public evidence record bound to an envelope hash.
func NewBlameEvidence(env Envelope, kind EvidenceKind, reason string, inputs []EvidenceField) (*BlameEvidence, error) {
	payloadHash := sha256.Sum256(env.Payload)
	evidence := &BlameEvidence{
		Version:        Version,
		Protocol:       env.Protocol,
		SessionID:      env.SessionID,
		Round:          env.Round,
		From:           env.From,
		To:             env.To,
		PayloadType:    env.PayloadType,
		PayloadHash:    payloadHash[:],
		TranscriptHash: slices.Clone(env.TranscriptHash[:]),
		Kind:           kind,
		Reason:         reason,
		PublicInputs:   cloneEvidenceFields(inputs),
	}
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	return evidence, nil
}

// Validate checks structural invariants for a public blame evidence record.
func (e *BlameEvidence) Validate() error {
	if e == nil {
		return errors.New("nil blame evidence")
	}
	if e.Version != Version {
		return fmt.Errorf("unexpected evidence version %d", e.Version)
	}
	if e.Protocol == "" {
		return errors.New("missing evidence protocol")
	}
	if e.PayloadType == "" {
		return errors.New("missing evidence payload type")
	}
	if len(e.PayloadHash) != sha256.Size {
		return errors.New("invalid evidence payload hash")
	}
	if len(e.TranscriptHash) != 0 && len(e.TranscriptHash) != sha256.Size {
		return errors.New("invalid evidence transcript hash")
	}
	if e.Kind == "" {
		return errors.New("missing evidence kind")
	}
	if e.Reason == "" {
		return errors.New("missing evidence reason")
	}
	limits := DefaultLimits()
	if len(e.Reason) > limits.MaxEvidenceReasonBytes {
		return fmt.Errorf("evidence reason too long: %d > %d", len(e.Reason), limits.MaxEvidenceReasonBytes)
	}
	if err := normalizeEvidenceFields(e.PublicInputs); err != nil {
		return err
	}
	return nil
}

// MarshalBinary encodes BlameEvidence using strict canonical TLV wire format.
func (e *BlameEvidence) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	fields := make([]EvidenceField, len(e.PublicInputs))
	for i, f := range e.PublicInputs {
		fields[i] = f.Clone()
	}
	if err := normalizeEvidenceFields(fields); err != nil {
		return nil, err
	}
	limits := DefaultLimits()
	if len(e.PayloadType) > limits.MaxPayloadTypeBytes {
		return nil, fmt.Errorf("evidence payload type too long: %d > %d", len(e.PayloadType), limits.MaxPayloadTypeBytes)
	}
	if len(e.Reason) > limits.MaxEvidenceReasonBytes {
		return nil, fmt.Errorf("evidence reason too long: %d > %d", len(e.Reason), limits.MaxEvidenceReasonBytes)
	}
	if len(fields) > limits.MaxEvidenceFieldCount {
		return nil, fmt.Errorf("evidence field count too large: %d > %d", len(fields), limits.MaxEvidenceFieldCount)
	}
	for _, f := range fields {
		if len(f.Key) > limits.MaxEvidenceFieldKeyBytes {
			return nil, fmt.Errorf("evidence field key too long: %d > %d", len(f.Key), limits.MaxEvidenceFieldKeyBytes)
		}
		if len(f.Value) > limits.MaxEvidenceFieldValueBytes {
			return nil, fmt.Errorf("evidence field value too long: %d > %d", len(f.Value), limits.MaxEvidenceFieldValueBytes)
		}
	}
	publicInputsBytes := encodeEvidenceFields(fields)
	return wire.Marshal(Version, blameWireType, []wire.Field{
		{Tag: blameFieldVersion, Value: wire.Uint16(e.Version)},
		{Tag: blameFieldProtocol, Value: []byte(e.Protocol)},
		{Tag: blameFieldSessionID, Value: e.SessionID[:]},
		{Tag: blameFieldRound, Value: []byte{e.Round}},
		{Tag: blameFieldFrom, Value: wire.Uint32(uint32(e.From))},
		{Tag: blameFieldTo, Value: wire.Uint32(uint32(e.To))},
		{Tag: blameFieldPayloadType, Value: []byte(e.PayloadType)},
		{Tag: blameFieldPayloadHash, Value: wire.NonNilBytes(e.PayloadHash)},
		{Tag: blameFieldTranscriptHash, Value: wire.NonNilBytes(e.TranscriptHash)},
		{Tag: blameFieldKind, Value: []byte(e.Kind)},
		{Tag: blameFieldReason, Value: []byte(e.Reason)},
		{Tag: blameFieldPublicInputs, Value: wire.NonNilBytes(publicInputsBytes)},
	})
}

// UnmarshalBlameEvidence decodes and validates public blame evidence.
func UnmarshalBlameEvidence(in []byte) (*BlameEvidence, error) {
	limits := DefaultLimits()
	if len(in) == 0 {
		return nil, errors.New("empty blame evidence")
	}
	if len(in) > limits.MaxBlameEvidenceBytes {
		return nil, fmt.Errorf("blame evidence too large: %d > %d", len(in), limits.MaxBlameEvidenceBytes)
	}
	version, fields, err := wire.UnmarshalWithLimits(in, blameWireType, wire.Limits{
		MaxTotalBytes: limits.MaxBlameEvidenceBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})
	if err != nil {
		return nil, err
	}
	if version != Version {
		return nil, fmt.Errorf("unexpected blame evidence wire version %d", version)
	}
	if err := wire.RequireExactTags(fields,
		blameFieldVersion,
		blameFieldProtocol,
		blameFieldSessionID,
		blameFieldRound,
		blameFieldFrom,
		blameFieldTo,
		blameFieldPayloadType,
		blameFieldPayloadHash,
		blameFieldTranscriptHash,
		blameFieldKind,
		blameFieldReason,
		blameFieldPublicInputs,
	); err != nil {
		return nil, err
	}
	evVersion, err := wire.DecodeUint16(fields[0].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid blame evidence version: %w", err)
	}
	if evVersion != Version {
		return nil, fmt.Errorf("unexpected blame evidence version %d", evVersion)
	}
	protocol := fields[1].Value
	if len(protocol) == 0 {
		return nil, errors.New("missing blame evidence protocol")
	}
	session, err := SessionIDFromBytes(fields[2].Value)
	if err != nil {
		return nil, err
	}
	round := fields[3].Value
	if len(round) != 1 {
		return nil, errors.New("invalid blame evidence round")
	}
	from, err := wire.DecodeUint32(fields[4].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid blame evidence from: %w", err)
	}
	to, err := wire.DecodeUint32(fields[5].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid blame evidence to: %w", err)
	}
	payloadType := fields[6].Value
	if len(payloadType) == 0 {
		return nil, errors.New("missing blame evidence payload type")
	}
	if len(payloadType) > limits.MaxPayloadTypeBytes {
		return nil, fmt.Errorf("blame evidence payload type too long: %d > %d", len(payloadType), limits.MaxPayloadTypeBytes)
	}
	payloadHash := fields[7].Value
	if len(payloadHash) != sha256.Size {
		return nil, errors.New("invalid blame evidence payload hash")
	}
	transcriptHash := fields[8].Value
	if len(transcriptHash) != 0 && len(transcriptHash) != sha256.Size {
		return nil, errors.New("invalid blame evidence transcript hash")
	}
	kind := fields[9].Value
	if len(kind) == 0 {
		return nil, errors.New("missing blame evidence kind")
	}
	reason := fields[10].Value
	if len(reason) == 0 {
		return nil, errors.New("missing blame evidence reason")
	}
	if len(reason) > limits.MaxEvidenceReasonBytes {
		return nil, fmt.Errorf("blame evidence reason too long: %d > %d", len(reason), limits.MaxEvidenceReasonBytes)
	}
	publicInputs, err := decodeEvidenceFields(fields[11].Value, limits)
	if err != nil {
		return nil, err
	}
	evidence := &BlameEvidence{
		Version:        evVersion,
		Protocol:       ProtocolID(protocol),
		SessionID:      session,
		Round:          round[0],
		From:           PartyID(from),
		To:             PartyID(to),
		PayloadType:    PayloadType(payloadType),
		PayloadHash:    slices.Clone(payloadHash),
		TranscriptHash: slices.Clone(transcriptHash),
		Kind:           EvidenceKind(kind),
		Reason:         string(reason),
		PublicInputs:   publicInputs,
	}
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	if err := normalizeEvidenceFields(evidence.PublicInputs); err != nil {
		return nil, err
	}
	return evidence, nil
}

// Hash returns the SHA-256 digest of the deterministic evidence encoding.
func (e *BlameEvidence) Hash() ([]byte, error) {
	encoded, err := e.MarshalBinary()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

// Field returns a copy of a named public input field.
func (e *BlameEvidence) Field(key string) ([]byte, bool) {
	if e == nil {
		return nil, false
	}
	for _, field := range e.PublicInputs {
		if field.Key == key {
			return slices.Clone(field.Value), true
		}
	}
	return nil, false
}

// encodeEvidenceFields encodes a list of evidence fields into a single byte slice.
// Format: uint32 count, then for each field: uint32 key-len + key + uint32 value-len + value.
// Callers must validate fields via normalizeEvidenceFields before calling.
func encodeEvidenceFields(fields []EvidenceField) []byte {
	if len(fields) == 0 {
		return nil
	}
	size := 4 // count
	for _, f := range fields {
		size += 4 + len(f.Key) + 4 + len(f.Value)
	}
	out := make([]byte, 0, size)
	out = append(out, wire.Uint32(uint32(len(fields)))...)
	for _, f := range fields {
		out = wire.AppendBytes(out, []byte(f.Key))
		out = wire.AppendBytes(out, f.Value)
	}
	return out
}

// decodeEvidenceFields decodes a list of evidence fields produced by encodeEvidenceFields.
func decodeEvidenceFields(raw []byte, limits Limits) ([]EvidenceField, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if int(count) > limits.MaxEvidenceFieldCount {
		return nil, fmt.Errorf("evidence field count too large: %d > %d", count, limits.MaxEvidenceFieldCount)
	}
	out := make([]EvidenceField, 0, count)
	for i := 0; i < int(count); i++ {
		keyBytes, next, err := wire.ReadBytesWithLimit(raw, offset, limits.MaxEvidenceFieldKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("evidence field %d key: %w", i, err)
		}
		offset = next
		value, next, err := wire.ReadBytesWithLimit(raw, offset, limits.MaxEvidenceFieldValueBytes)
		if err != nil {
			return nil, fmt.Errorf("evidence field %d value: %w", i, err)
		}
		offset = next
		out = append(out, EvidenceField{Key: string(keyBytes), Value: value})
	}
	if offset != len(raw) {
		return nil, errors.New("trailing evidence fields data")
	}
	return out, nil
}

func cloneEvidenceFields(in []EvidenceField) []EvidenceField {
	if len(in) == 0 {
		return nil
	}
	out := make([]EvidenceField, len(in))
	for i, field := range in {
		out[i] = field.Clone()
	}
	return out
}

func normalizeEvidenceFields(fields []EvidenceField) error {
	// Canonical field order keeps evidence hashes stable across processes and
	// avoids relying on caller-provided slice ordering.
	slices.SortFunc(fields, func(a, b EvidenceField) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return bytes.Compare(a.Value, b.Value)
	})
	for i, field := range fields {
		if field.Key == "" {
			return errors.New("empty evidence field key")
		}
		if field.Value == nil {
			return fmt.Errorf("nil evidence field %q", field.Key)
		}
		if i > 0 && fields[i-1].Key == field.Key {
			return fmt.Errorf("duplicate evidence field %q", field.Key)
		}
	}
	return nil
}
