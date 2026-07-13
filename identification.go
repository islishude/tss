package tss

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const identificationAlertDigestLabel = "github.com/islishude/tss/identification-alert/v1"

const (
	identificationRecordWireType    = "tss.identification-record"
	identificationRecordWireVersion = 1

	// IdentificationRecordEvidenceKey is the fixed BlameEvidence.PublicInputs
	// key carrying a canonical IdentificationRecord.
	IdentificationRecordEvidenceKey = "identification_record"
)

// IdentificationRecord contains the public statement needed to verify one
// identifiable-abort accusation. It must never contain protocol witnesses.
type IdentificationRecord struct {
	FailureClass         string          `wire:"1,string,max_bytes=identification_class"`
	AlertDigest          []byte          `wire:"2,bytes,len=32"`
	Accused              PartyID         `wire:"3,u32"`
	SignedEnvelopeA      []byte          `wire:"4,bytes,max_bytes=envelope"`
	SignedEnvelopeB      []byte          `wire:"5,bytes,max_bytes=envelope"`
	BroadcastCertificate []byte          `wire:"6,bytes,max_bytes=broadcast_certificate"`
	Statement            []byte          `wire:"7,bytes,max_bytes=identification_statement"`
	Proof                []byte          `wire:"8,bytes,max_bytes=zk_proof"`
	TranscriptHashes     []EvidenceField `wire:"9,recordlist,max_items=identification_hashes"`
}

// identificationRecordWire is the reflection codec shape used after the
// caller-selected limits have already been applied. It deliberately does not
// implement Validator: invoking IdentificationRecord.Validate from wire.Marshal
// or wire.Unmarshal would reapply the conservative default limits and make the
// explicit Figure 9 opt-in limits ineffective.
type identificationRecordWire IdentificationRecord

// WireType returns the canonical wire type identifier for the private codec shape.
func (identificationRecordWire) WireType() string { return identificationRecordWireType }

// WireVersion returns the wire format version for the private codec shape.
func (identificationRecordWire) WireVersion() uint16 { return identificationRecordWireVersion }

// WireType returns the canonical wire type identifier.
func (IdentificationRecord) WireType() string { return identificationRecordWireType }

// WireVersion returns the canonical wire version.
func (IdentificationRecord) WireVersion() uint16 { return identificationRecordWireVersion }

// Clone returns an independently owned record.
func (r IdentificationRecord) Clone() IdentificationRecord {
	return IdentificationRecord{
		FailureClass:         r.FailureClass,
		AlertDigest:          bytes.Clone(r.AlertDigest),
		Accused:              r.Accused,
		SignedEnvelopeA:      bytes.Clone(r.SignedEnvelopeA),
		SignedEnvelopeB:      bytes.Clone(r.SignedEnvelopeB),
		BroadcastCertificate: bytes.Clone(r.BroadcastCertificate),
		Statement:            bytes.Clone(r.Statement),
		Proof:                bytes.Clone(r.Proof),
		TranscriptHashes:     canonicalEvidenceFields(r.TranscriptHashes),
	}
}

// ComputeAlertDigest hashes the public failure class, artifacts, and trusted
// transcript hashes that existed before the identification proof was made.
func (r IdentificationRecord) ComputeAlertDigest() [32]byte {
	t := transcript.New(identificationAlertDigestLabel)
	t.AppendString("failure_class", r.FailureClass)
	t.AppendUint32("accused", r.Accused)
	t.AppendBytes("signed_envelope_a", r.SignedEnvelopeA)
	t.AppendBytes("signed_envelope_b", r.SignedEnvelopeB)
	t.AppendBytes("broadcast_certificate", r.BroadcastCertificate)
	t.AppendBytes("statement", r.Statement)
	t.AppendBytes("proof", r.Proof)
	for _, field := range canonicalEvidenceFields(r.TranscriptHashes) {
		t.AppendString("transcript_name", field.Key)
		t.AppendBytes("transcript_hash", field.Value)
	}
	return t.Sum32()
}

// BeforeMarshalWire canonicalizes named transcript hashes.
func (r *IdentificationRecord) BeforeMarshalWire() error {
	r.TranscriptHashes = canonicalEvidenceFields(r.TranscriptHashes)
	return nil
}

// Validate rejects incomplete, non-public, or non-canonical record shapes.
func (r *IdentificationRecord) Validate() error {
	return r.ValidateWithLimits(defaultIdentificationRecordLimits())
}

// ValidateWithLimits rejects incomplete, non-public, or non-canonical record
// shapes using explicit resource limits.
func (r *IdentificationRecord) ValidateWithLimits(limits IdentificationRecordLimits) error {
	if r == nil {
		return errors.New("nil identification record")
	}
	if r.FailureClass == "" || len(r.FailureClass) > limits.MaxFailureClassBytes {
		return errors.New("invalid identification failure class")
	}
	if len(r.AlertDigest) != sha256.Size {
		return errors.New("invalid identification alert digest")
	}
	expectedAlert := r.ComputeAlertDigest()
	if !bytes.Equal(r.AlertDigest, expectedAlert[:]) {
		return errors.New("identification alert digest mismatch")
	}
	if r.Accused == 0 || r.Accused == BroadcastPartyId {
		return errors.New("invalid identification accused party")
	}
	if len(r.SignedEnvelopeA) == 0 && len(r.BroadcastCertificate) == 0 && (len(r.Statement) == 0 || len(r.Proof) == 0) {
		return errors.New("identification record has no verifiable artifact")
	}
	if len(r.SignedEnvelopeA) > limits.MaxEnvelopeBytes || len(r.SignedEnvelopeB) > limits.MaxEnvelopeBytes {
		return errors.New("identification signed envelope exceeds hard cap")
	}
	if len(r.BroadcastCertificate) > limits.MaxBroadcastCertificateBytes {
		return errors.New("identification broadcast certificate exceeds hard cap")
	}
	if len(r.Statement) > limits.MaxStatementBytes {
		return errors.New("identification statement exceeds hard cap")
	}
	if len(r.Proof) > limits.MaxProofBytes {
		return errors.New("identification proof exceeds hard cap")
	}
	if len(r.TranscriptHashes) > limits.MaxTranscriptHashCount {
		return errors.New("too many identification transcript hashes")
	}
	seen := make(map[string]struct{}, len(r.TranscriptHashes))
	for _, field := range r.TranscriptHashes {
		if field.Key == "" || len(field.Key) > limits.MaxTranscriptHashKeyBytes {
			return errors.New("invalid identification transcript hash key")
		}
		if len(field.Value) != sha256.Size {
			return fmt.Errorf("identification transcript hash %q has wrong length", field.Key)
		}
		if _, ok := seen[field.Key]; ok {
			return fmt.Errorf("duplicate identification transcript hash %q", field.Key)
		}
		seen[field.Key] = struct{}{}
	}
	if !slices.IsSortedFunc(r.TranscriptHashes, func(a, b EvidenceField) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return bytes.Compare(a.Value, b.Value)
	}) {
		return errors.New("identification transcript hashes are not canonical")
	}
	return nil
}

// MarshalBinary returns the strict canonical wire encoding.
func (r *IdentificationRecord) MarshalBinary() ([]byte, error) {
	return r.MarshalBinaryWithLimits(defaultIdentificationRecordLimits())
}

// MarshalBinaryWithLimits returns the strict canonical wire encoding under
// explicit resource limits.
func (r *IdentificationRecord) MarshalBinaryWithLimits(limits IdentificationRecordLimits) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil identification record")
	}
	clone := r.Clone()
	if err := clone.BeforeMarshalWire(); err != nil {
		return nil, err
	}
	if err := clone.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	wireRecord := identificationRecordWire(clone)
	encoded, err := wire.Marshal(&wireRecord, wire.WithFieldLimitsForMarshal(identificationFieldLimits(limits)))
	if err != nil {
		return nil, err
	}
	if len(encoded) > limits.MaxBytes {
		return nil, fmt.Errorf("identification record too large: %d > %d", len(encoded), limits.MaxBytes)
	}
	return encoded, nil
}

// UnmarshalBinary decodes a strict canonical wire record.
func (r *IdentificationRecord) UnmarshalBinary(in []byte) error {
	return r.UnmarshalBinaryWithLimits(in, defaultIdentificationRecordLimits())
}

// UnmarshalBinaryWithLimits decodes a strict canonical identification record
// under explicit resource limits.
func (r *IdentificationRecord) UnmarshalBinaryWithLimits(in []byte, limits IdentificationRecordLimits) error {
	if len(in) == 0 || len(in) > limits.MaxBytes {
		return errors.New("invalid identification record size")
	}
	var wireRecord identificationRecordWire
	if err := wire.Unmarshal(in, &wireRecord,
		wire.WithFrameLimits(wire.FrameLimits{MaxTotalBytes: limits.MaxBytes, MaxFields: limits.TLV.MaxFields, MaxFieldBytes: limits.TLV.MaxFieldBytes}),
		wire.WithFieldLimits(identificationFieldLimits(limits)),
	); err != nil {
		return err
	}
	decoded := IdentificationRecord(wireRecord)
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*r = decoded
	return nil
}

func defaultIdentificationRecordLimits() IdentificationRecordLimits {
	return IdentificationRecordLimits{
		MaxBytes:                     DefaultMaxBlameEvidenceBytes,
		MaxFailureClassBytes:         128,
		MaxEnvelopeBytes:             DefaultMaxEnvelopeBytes,
		MaxBroadcastCertificateBytes: DefaultMaxBlameEvidenceBytes,
		MaxStatementBytes:            DefaultMaxZKProofBytes,
		MaxProofBytes:                DefaultMaxZKProofBytes,
		MaxTranscriptHashCount:       DefaultMaxEvidenceFieldCount,
		MaxTranscriptHashKeyBytes:    DefaultMaxEvidenceFieldKeyBytes,
		TLV: TLVLimits{
			MaxFields:     DefaultMaxWireFields,
			MaxFieldBytes: DefaultMaxWireFieldBytes,
		},
	}
}

// DefaultIdentificationRecordLimits returns a caller-owned copy of the
// conservative limits used by IdentificationRecord.MarshalBinary and
// IdentificationRecord.UnmarshalBinary.
func DefaultIdentificationRecordLimits() IdentificationRecordLimits {
	return defaultIdentificationRecordLimits()
}

func identificationFieldLimits(limits IdentificationRecordLimits) wire.FieldLimits {
	return wire.FieldLimits{
		"identification_class":     limits.MaxFailureClassBytes,
		"envelope":                 limits.MaxEnvelopeBytes,
		"broadcast_certificate":    limits.MaxBroadcastCertificateBytes,
		"identification_statement": limits.MaxStatementBytes,
		"zk_proof":                 limits.MaxProofBytes,
		"identification_hashes":    limits.MaxTranscriptHashCount,
		"evidence_field_key":       limits.MaxTranscriptHashKeyBytes,
		"evidence_field_value":     sha256.Size,
	}
}

// IdentificationEvidenceField encodes record under the fixed evidence key.
func IdentificationEvidenceField(record *IdentificationRecord) (EvidenceField, error) {
	return IdentificationEvidenceFieldWithLimits(record, defaultIdentificationRecordLimits())
}

// IdentificationEvidenceFieldWithLimits encodes a record under the fixed
// evidence key using explicit resource limits.
func IdentificationEvidenceFieldWithLimits(record *IdentificationRecord, limits IdentificationRecordLimits) (EvidenceField, error) {
	encoded, err := record.MarshalBinaryWithLimits(limits)
	if err != nil {
		return EvidenceField{}, err
	}
	return EvidenceField{Key: IdentificationRecordEvidenceKey, Value: encoded}, nil
}
