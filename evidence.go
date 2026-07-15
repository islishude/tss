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
	// EvidenceKindPaillierAux marks invalid Paillier, Ring-Pedersen, or
	// receiver-specific factor-proof auxiliary material in any lifecycle.
	EvidenceKindPaillierAux EvidenceKind = "paillier_aux"
	// EvidenceKindKeygenShare marks a DKG share that does not match commitments.
	EvidenceKindKeygenShare EvidenceKind = "keygen_share"
	// EvidenceKindRefreshShare marks a proactive refresh share that does not match commitments.
	EvidenceKindRefreshShare EvidenceKind = "refresh_share"
	// EvidenceKindRefreshCommitment marks invalid proactive-refresh polynomial commitments.
	EvidenceKindRefreshCommitment EvidenceKind = "refresh_commitment"
	// EvidenceKindReshareShare marks a CGGMP21 reshare share that does not match commitments.
	EvidenceKindReshareShare EvidenceKind = "reshare_share"
	// EvidenceKindReshareCommitment marks invalid CGGMP21 reshare dealer commitments.
	EvidenceKindReshareCommitment EvidenceKind = "reshare_commitment"
	// EvidenceKindPresignRound1 marks invalid presign nonce commitment material.
	EvidenceKindPresignRound1 EvidenceKind = "presign_round1"
	// EvidenceKindPresignRound2 marks invalid pairwise MtA response material.
	EvidenceKindPresignRound2 EvidenceKind = "presign_round2"
	// EvidenceKindPresignRound3 marks invalid presign delta broadcast material.
	EvidenceKindPresignRound3 EvidenceKind = "presign_round3"
	// EvidenceKindPresignRedAlert marks an invalid Figure 9 presign red-alert proof.
	EvidenceKindPresignRedAlert EvidenceKind = "presign_red_alert"
	// EvidenceKindSignPartial marks invalid online signing partial material.
	EvidenceKindSignPartial EvidenceKind = "sign_partial"
	// EvidenceKindAggregateSign marks a final aggregate signature verification failure.
	EvidenceKindAggregateSign EvidenceKind = "aggregate_signature"
	// EvidenceKindFrostKeygenShare marks an invalid FROST DKG share.
	EvidenceKindFrostKeygenShare EvidenceKind = "frost_keygen_share"
	// EvidenceKindFrostKeygenCommitment marks invalid public FROST DKG commitment or proof material.
	EvidenceKindFrostKeygenCommitment EvidenceKind = "frost_keygen_commitment"
	// EvidenceKindFrostReshareShare marks an invalid FROST reshare share.
	EvidenceKindFrostReshareShare EvidenceKind = "frost_reshare_share"
	// EvidenceKindFrostNonceCommitment marks an invalid FROST signing nonce commitment.
	EvidenceKindFrostNonceCommitment EvidenceKind = "frost_nonce_commitment"
	// EvidenceKindFrostPartialSignature marks an invalid FROST partial signature.
	EvidenceKindFrostPartialSignature EvidenceKind = "frost_partial_signature"
	// EvidenceKindFrostAggregateSignature marks a failed FROST aggregate Ed25519 signature.
	EvidenceKindFrostAggregateSignature EvidenceKind = "frost_aggregate_signature"
)

// blameWireType is the TLV type identifier for blame evidence records.
const blameWireType = "tss.blame"

const blameWireVersion uint16 = 1

// EvidenceField carries one public input or public-input hash for blame evidence.
type EvidenceField struct {
	Key   string `wire:"1,max_bytes=evidence_field_key"`
	Value []byte `wire:"2,max_bytes=evidence_field_value"`
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
	Protocol       ProtocolID      `wire:"1"`
	SessionID      SessionID       `wire:"2,len=32"`
	Round          uint8           `wire:"3"`
	From           PartyID         `wire:"4"`
	To             PartyID         `wire:"5"`
	PayloadType    PayloadType     `wire:"6,max_bytes=payload_type"`
	PayloadHash    []byte          `wire:"7,len=32"`
	EnvelopeDigest []byte          `wire:"8"`
	Kind           EvidenceKind    `wire:"9"`
	Reason         string          `wire:"10,max_bytes=evidence_reason"`
	PublicInputs   []EvidenceField `wire:"11,max_items=evidence_fields"`
}

// blameEvidenceWire has the exact canonical wire schema of BlameEvidence but
// deliberately does not implement Validator. Limits-aware entry points first
// validate against their caller-supplied EvidenceLimits and then encode or
// decode this private object-level wire type. Encoding BlameEvidence directly
// would make internal/wire invoke BlameEvidence.Validate a second time with the
// conservative defaults, incorrectly rejecting explicitly authorized Figure 9
// public proof records.
type blameEvidenceWire BlameEvidence

// WireType returns the canonical wire type identifier for the private codec shape.
func (blameEvidenceWire) WireType() string { return blameWireType }

// WireVersion returns the wire format version for the private codec shape.
func (blameEvidenceWire) WireVersion() uint16 { return blameWireVersion }

// WireType returns the canonical wire type identifier for BlameEvidence.
func (BlameEvidence) WireType() string { return blameWireType }

// WireVersion returns the wire format version for BlameEvidence.
func (BlameEvidence) WireVersion() uint16 { return blameWireVersion }

// defaultEvidenceLimits returns conservative evidence limits suitable for
// production use.
func defaultEvidenceLimits() EvidenceLimits {
	return EvidenceLimits{
		MaxBytes:            DefaultMaxBlameEvidenceBytes,
		MaxReasonBytes:      DefaultMaxEvidenceReasonBytes,
		MaxFieldCount:       DefaultMaxEvidenceFieldCount,
		MaxFieldKeyBytes:    DefaultMaxEvidenceFieldKeyBytes,
		MaxFieldValueBytes:  DefaultMaxEvidenceFieldValueBytes,
		MaxPayloadTypeBytes: DefaultMaxPayloadTypeBytes,
		TLV: TLVLimits{
			MaxFields:     DefaultMaxWireFields,
			MaxFieldBytes: DefaultMaxWireFieldBytes,
		},
	}
}

// DefaultEvidenceLimits returns a caller-owned copy of the conservative
// production limits used by NewBlameEvidence and BlameEvidence.MarshalBinary.
func DefaultEvidenceLimits() EvidenceLimits { return defaultEvidenceLimits() }

// evidenceFieldLimits converts EvidenceLimits into wire.FieldLimits for
// use with wire.Marshal / wire.Unmarshal.
func evidenceFieldLimits(l EvidenceLimits) wire.FieldLimits {
	return wire.FieldLimits{
		"payload_type":         l.MaxPayloadTypeBytes,
		"evidence_reason":      l.MaxReasonBytes,
		"evidence_fields":      l.MaxFieldCount,
		"evidence_field_key":   l.MaxFieldKeyBytes,
		"evidence_field_value": l.MaxFieldValueBytes,
	}
}

// NewBlameEvidence builds a public evidence record bound to an envelope hash.
// PublicInputs are stored in canonical order so that logically equivalent
// evidence records produce identical hashes regardless of caller-provided
// slice ordering.
func NewBlameEvidence(env Envelope, kind EvidenceKind, reason string, inputs []EvidenceField) (*BlameEvidence, error) {
	return NewBlameEvidenceWithLimits(env, kind, reason, inputs, defaultEvidenceLimits())
}

// NewBlameEvidenceWithLimits builds public evidence using explicit resource
// limits. This is intended for protocol phases whose canonical public proof is
// deliberately larger than the conservative default; it does not widen any
// default decoder or encoder.
func NewBlameEvidenceWithLimits(env Envelope, kind EvidenceKind, reason string, inputs []EvidenceField, limits EvidenceLimits) (*BlameEvidence, error) {
	payloadHash := sha256.Sum256(env.Payload)
	envelopeDigest := env.Digest()
	evidence := &BlameEvidence{
		Protocol:       env.Protocol,
		SessionID:      env.SessionID,
		Round:          env.Round,
		From:           env.From,
		To:             env.To,
		PayloadType:    env.PayloadType,
		PayloadHash:    payloadHash[:],
		EnvelopeDigest: envelopeDigest[:],
		Kind:           kind,
		Reason:         reason,
		PublicInputs:   canonicalEvidenceFields(inputs),
	}
	if err := evidence.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return evidence, nil
}

// Validate checks structural invariants for a public blame evidence record
// using conservative default limits. Use [BlameEvidence.ValidateWithLimits]
// for explicit control.
func (e *BlameEvidence) Validate() error {
	return e.ValidateWithLimits(defaultEvidenceLimits())
}

// ValidateWithLimits checks structural invariants for a public blame evidence
// record against the provided limits. Canonical ordering of PublicInputs is
// handled by [BlameEvidence.BeforeMarshalWire], which is called automatically
// by wire.Marshal before encoding.
func (e *BlameEvidence) ValidateWithLimits(l EvidenceLimits) error {
	if e == nil {
		return errors.New("nil blame evidence")
	}
	if e.Protocol == "" {
		return errors.New("missing evidence protocol")
	}
	if e.PayloadType == "" {
		return errors.New("missing evidence payload type")
	}
	if len(e.PayloadType) > l.MaxPayloadTypeBytes {
		return fmt.Errorf("evidence payload type too long: %d > %d", len(e.PayloadType), l.MaxPayloadTypeBytes)
	}
	if len(e.PayloadHash) != sha256.Size {
		return errors.New("invalid evidence payload hash")
	}
	if len(e.EnvelopeDigest) != 0 && len(e.EnvelopeDigest) != sha256.Size {
		return errors.New("invalid evidence envelope digest")
	}
	if e.Kind == "" {
		return errors.New("missing evidence kind")
	}
	if !validEvidenceKind(e.Kind) {
		return fmt.Errorf("unknown evidence kind %q", e.Kind)
	}
	if e.Reason == "" {
		return errors.New("missing evidence reason")
	}
	if len(e.Reason) > l.MaxReasonBytes {
		return fmt.Errorf("evidence reason too long: %d > %d", len(e.Reason), l.MaxReasonBytes)
	}
	if fl := len(e.PublicInputs); fl > l.MaxFieldCount {
		return fmt.Errorf("evidence field count too large: %d > %d", fl, l.MaxFieldCount)
	}
	seen := make(map[string]struct{}, len(e.PublicInputs))
	for _, field := range e.PublicInputs {
		if field.Key == "" {
			return errors.New("empty evidence field key")
		}
		if fl := len(field.Key); fl > l.MaxFieldKeyBytes {
			return fmt.Errorf("evidence field key too long: %d > %d", fl, l.MaxFieldKeyBytes)
		}
		if _, ok := seen[field.Key]; ok {
			return fmt.Errorf("duplicate evidence field %q", field.Key)
		}
		seen[field.Key] = struct{}{}
		if field.Value == nil {
			return fmt.Errorf("nil evidence field %q", field.Key)
		}
		if fl := len(field.Value); fl > l.MaxFieldValueBytes {
			return fmt.Errorf("evidence field value too long: %d > %d", fl, l.MaxFieldValueBytes)
		}
	}
	return nil
}

// BeforeMarshalWire canonicalizes the PublicInputs field ordering before
// encoding, so that logically equivalent evidence records produce identical
// wire representations regardless of caller-provided slice ordering.
func (e *BlameEvidence) BeforeMarshalWire() error {
	e.PublicInputs = canonicalEvidenceFields(e.PublicInputs)
	return nil
}

// MarshalBinary encodes BlameEvidence using the object-level wire codec with
// conservative default limits. Use [MarshalEvidenceWithLimits] for explicit control.
func (e *BlameEvidence) MarshalBinary() ([]byte, error) {
	return e.MarshalBinaryWithLimits(defaultEvidenceLimits())
}

// MarshalBinaryWithLimits encodes BlameEvidence using the object-level wire
// codec with explicit limits.
func (e *BlameEvidence) MarshalBinaryWithLimits(l EvidenceLimits) ([]byte, error) {
	return MarshalEvidenceWithLimits(e, l)
}

// MarshalEvidenceWithLimits encodes BlameEvidence using the object-level wire
// codec with explicit limits. Fields are sorted into canonical order so that
// logically equivalent evidence records produce identical hashes.
func MarshalEvidenceWithLimits(e *BlameEvidence, l EvidenceLimits) ([]byte, error) {
	if err := e.ValidateWithLimits(l); err != nil {
		return nil, err
	}
	prepared := *e
	prepared.PublicInputs = canonicalEvidenceFields(e.PublicInputs)
	wireValue := blameEvidenceWire(prepared)
	return wire.Marshal(&wireValue, wire.WithFieldLimitsForMarshal(evidenceFieldLimits(l)))
}

// UnmarshalBlameEvidenceWithLimits decodes and validates public blame evidence
// with explicit size limits.
func UnmarshalBlameEvidenceWithLimits(in []byte, l EvidenceLimits) (*BlameEvidence, error) {
	return DecodeBinaryWithLimits[BlameEvidence](in, l)
}

// UnmarshalBinary decodes and validates public blame evidence using
// conservative default limits.
func (e *BlameEvidence) UnmarshalBinary(in []byte) error {
	return e.UnmarshalBinaryWithLimits(in, defaultEvidenceLimits())
}

// UnmarshalBinaryWithLimits decodes and validates public blame evidence into
// the receiver with explicit size limits.
func (e *BlameEvidence) UnmarshalBinaryWithLimits(in []byte, l EvidenceLimits) error {
	if len(in) == 0 {
		return errors.New("empty blame evidence")
	}

	if len(in) > l.MaxBytes {
		return fmt.Errorf("blame evidence too large: %d > %d", len(in), l.MaxBytes)
	}

	var wireValue blameEvidenceWire
	if err := wire.Unmarshal(
		in,
		&wireValue,
		wire.WithFrameLimits(wire.FrameLimits{
			MaxTotalBytes: l.MaxBytes,
			MaxFields:     l.TLV.MaxFields,
			MaxFieldBytes: l.TLV.MaxFieldBytes,
		}),
		wire.WithFieldLimits(evidenceFieldLimits(l)),
	); err != nil {
		return err
	}
	evidence := BlameEvidence(wireValue)
	if err := evidence.ValidateWithLimits(l); err != nil {
		return err
	}

	*e = evidence
	return nil
}

func validEvidenceKind(kind EvidenceKind) bool {
	switch kind {
	case EvidenceKindKeygenCommitment,
		EvidenceKindPaillierAux,
		EvidenceKindKeygenShare,
		EvidenceKindRefreshCommitment,
		EvidenceKindRefreshShare,
		EvidenceKindReshareCommitment,
		EvidenceKindReshareShare,
		EvidenceKindPresignRound1,
		EvidenceKindPresignRound2,
		EvidenceKindPresignRound3,
		EvidenceKindPresignRedAlert,
		EvidenceKindSignPartial,
		EvidenceKindAggregateSign,
		EvidenceKindFrostKeygenCommitment,
		EvidenceKindFrostKeygenShare,
		EvidenceKindFrostReshareShare,
		EvidenceKindFrostNonceCommitment,
		EvidenceKindFrostPartialSignature,
		EvidenceKindFrostAggregateSignature:
		return true
	default:
		return false
	}
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

// canonicalEvidenceFields returns a sorted copy of the evidence fields.
// Canonical order (by key, then value) keeps evidence hashes stable across
// processes — two callers that provide the same logical fields in different
// orders produce the same encoding and therefore the same hash.
func canonicalEvidenceFields(fields []EvidenceField) []EvidenceField {
	if len(fields) == 0 {
		return nil
	}
	sorted := CloneSlice(fields)
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
