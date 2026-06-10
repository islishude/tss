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
// PublicInputs are stored in canonical order so that logically equivalent
// evidence records produce identical hashes regardless of caller-provided
// slice ordering.
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
		PublicInputs:   canonicalEvidenceFields(inputs),
	}
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	return evidence, nil
}

// Validate checks structural invariants for a public blame evidence record.
// It does not mutate the receiver — callers that need canonical field ordering
// for stable hashing must use [BlameEvidence.MarshalBinary], which sorts a copy
// before encoding.
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
	limits := DefaultLimits()
	if len(e.PayloadType) > limits.MaxPayloadTypeBytes {
		return fmt.Errorf("evidence payload type too long: %d > %d", len(e.PayloadType), limits.MaxPayloadTypeBytes)
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
	if len(e.Reason) > limits.MaxEvidenceReasonBytes {
		return fmt.Errorf("evidence reason too long: %d > %d", len(e.Reason), limits.MaxEvidenceReasonBytes)
	}
	if fl := len(e.PublicInputs); fl > limits.MaxEvidenceFieldCount {
		return fmt.Errorf("evidence field count too large: %d > %d", fl, limits.MaxEvidenceFieldCount)
	}
	seen := make(map[string]struct{}, len(e.PublicInputs))
	for _, field := range e.PublicInputs {
		if field.Key == "" {
			return errors.New("empty evidence field key")
		}
		if fl := len(field.Key); fl > limits.MaxEvidenceFieldKeyBytes {
			return fmt.Errorf("evidence field key too long: %d > %d", fl, limits.MaxEvidenceFieldKeyBytes)
		}
		if _, ok := seen[field.Key]; ok {
			return fmt.Errorf("duplicate evidence field %q", field.Key)
		}
		seen[field.Key] = struct{}{}
		if field.Value == nil {
			return fmt.Errorf("nil evidence field %q", field.Key)
		}
		if fl := len(field.Value); fl > limits.MaxEvidenceFieldValueBytes {
			return fmt.Errorf("evidence field value too long: %d > %d", fl, limits.MaxEvidenceFieldValueBytes)
		}
	}
	return nil
}

// blameEvidenceWire is the wire DTO for BlameEvidence.
type blameEvidenceWire struct {
	Version        uint16       `wire:"1,u16"`
	Protocol       ProtocolID   `wire:"2,string"`
	SessionID      []byte       `wire:"3,bytes,len=32"`
	Round          uint8        `wire:"4,u8"`
	From           PartyID      `wire:"5,u32"`
	To             PartyID      `wire:"6,u32"`
	PayloadType    PayloadType  `wire:"7,string"`
	PayloadHash    []byte       `wire:"8,bytes"`
	TranscriptHash []byte       `wire:"9,bytes"`
	Kind           EvidenceKind `wire:"10,string"`
	Reason         string       `wire:"11,string"`
	PublicInputs   []byte       `wire:"12,bytes"`
}

// WireType returns the canonical wire type identifier for blameEvidenceWire.
func (blameEvidenceWire) WireType() string { return blameWireType }

// WireVersion returns the wire format version for blameEvidenceWire.
func (blameEvidenceWire) WireVersion() uint16 { return Version }

// MarshalBinary encodes BlameEvidence using the object-level wire codec.
// Fields are sorted into canonical order so that logically equivalent evidence
// records produce identical hashes regardless of caller-provided slice ordering.
func (e *BlameEvidence) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	fields := canonicalEvidenceFields(e.PublicInputs)
	return wire.Marshal(blameEvidenceWire{
		Version:        e.Version,
		Protocol:       e.Protocol,
		SessionID:      e.SessionID[:],
		Round:          e.Round,
		From:           e.From,
		To:             e.To,
		PayloadType:    e.PayloadType,
		PayloadHash:    e.PayloadHash,
		TranscriptHash: e.TranscriptHash,
		Kind:           e.Kind,
		Reason:         e.Reason,
		PublicInputs:   encodeEvidenceFields(fields),
	})
}

// UnmarshalBlameEvidence decodes and validates public blame evidence.
func UnmarshalBlameEvidence(in []byte) (*BlameEvidence, error) {
	if len(in) == 0 {
		return nil, errors.New("empty blame evidence")
	}
	limits := DefaultLimits()
	if len(in) > limits.MaxBlameEvidenceBytes {
		return nil, fmt.Errorf("blame evidence too large: %d > %d", len(in), limits.MaxBlameEvidenceBytes)
	}
	var w blameEvidenceWire
	if err := wire.Unmarshal(in, &w, wire.WithLimits(wire.Limits{
		MaxTotalBytes: limits.MaxBlameEvidenceBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})); err != nil {
		return nil, err
	}
	if w.Version != Version {
		return nil, fmt.Errorf("unexpected blame evidence version %d", w.Version)
	}
	if w.Protocol == "" {
		return nil, errors.New("missing blame evidence protocol")
	}
	if w.PayloadType == "" {
		return nil, errors.New("missing blame evidence payload type")
	}
	if len(w.PayloadType) > limits.MaxPayloadTypeBytes {
		return nil, fmt.Errorf("blame evidence payload type too long: %d > %d", len(w.PayloadType), limits.MaxPayloadTypeBytes)
	}
	if len(w.PayloadHash) != sha256.Size {
		return nil, errors.New("invalid blame evidence payload hash")
	}
	if len(w.TranscriptHash) != 0 && len(w.TranscriptHash) != sha256.Size {
		return nil, errors.New("invalid blame evidence transcript hash")
	}
	if w.Kind == "" {
		return nil, errors.New("missing blame evidence kind")
	}
	if w.Reason == "" {
		return nil, errors.New("missing blame evidence reason")
	}
	if len(w.Reason) > limits.MaxEvidenceReasonBytes {
		return nil, fmt.Errorf("blame evidence reason too long: %d > %d", len(w.Reason), limits.MaxEvidenceReasonBytes)
	}
	session, err := SessionIDFromBytes(w.SessionID)
	if err != nil {
		return nil, err
	}
	publicInputs, err := decodeEvidenceFields(w.PublicInputs, limits)
	if err != nil {
		return nil, err
	}
	evidence := &BlameEvidence{
		Version:        w.Version,
		Protocol:       w.Protocol,
		SessionID:      session,
		Round:          w.Round,
		From:           w.From,
		To:             w.To,
		PayloadType:    w.PayloadType,
		PayloadHash:    slices.Clone(w.PayloadHash),
		TranscriptHash: slices.Clone(w.TranscriptHash),
		Kind:           w.Kind,
		Reason:         w.Reason,
		PublicInputs:   publicInputs,
	}
	if err := evidence.Validate(); err != nil {
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

// canonicalEvidenceFields returns a sorted copy of the evidence fields.
// Canonical order (by key, then value) keeps evidence hashes stable across
// processes — two callers that provide the same logical fields in different
// orders produce the same encoding and therefore the same hash.
func canonicalEvidenceFields(fields []EvidenceField) []EvidenceField {
	if len(fields) == 0 {
		return nil
	}
	sorted := cloneEvidenceFields(fields)
	slices.SortFunc(sorted, func(a, b EvidenceField) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return bytes.Compare(a.Value, b.Value)
	})
	return sorted
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
