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
	if r == nil {
		return errors.New("nil identification record")
	}
	if r.FailureClass == "" || len(r.FailureClass) > 128 {
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
	if len(r.SignedEnvelopeA) > DefaultMaxEnvelopeBytes || len(r.SignedEnvelopeB) > DefaultMaxEnvelopeBytes {
		return errors.New("identification signed envelope exceeds hard cap")
	}
	if len(r.Proof) > DefaultMaxZKProofBytes {
		return errors.New("identification proof exceeds hard cap")
	}
	seen := make(map[string]struct{}, len(r.TranscriptHashes))
	for _, field := range r.TranscriptHashes {
		if field.Key == "" || len(field.Key) > DefaultMaxEvidenceFieldKeyBytes {
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
	if r == nil {
		return nil, errors.New("nil identification record")
	}
	clone := r.Clone()
	if err := clone.BeforeMarshalWire(); err != nil {
		return nil, err
	}
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(&clone, wire.WithFieldLimitsForMarshal(identificationFieldLimits()))
}

// UnmarshalBinary decodes a strict canonical wire record.
func (r *IdentificationRecord) UnmarshalBinary(in []byte) error {
	if len(in) == 0 || len(in) > DefaultMaxBlameEvidenceBytes {
		return errors.New("invalid identification record size")
	}
	var decoded IdentificationRecord
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.FrameLimits{MaxTotalBytes: DefaultMaxBlameEvidenceBytes, MaxFields: DefaultMaxWireFields, MaxFieldBytes: DefaultMaxWireFieldBytes}),
		wire.WithFieldLimits(identificationFieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*r = decoded
	return nil
}

func identificationFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"identification_class":     128,
		"envelope":                 DefaultMaxEnvelopeBytes,
		"broadcast_certificate":    DefaultMaxBlameEvidenceBytes,
		"identification_statement": DefaultMaxZKProofBytes,
		"zk_proof":                 DefaultMaxZKProofBytes,
		"identification_hashes":    DefaultMaxEvidenceFieldCount,
		"evidence_field_key":       DefaultMaxEvidenceFieldKeyBytes,
		"evidence_field_value":     sha256.Size,
	}
}

// IdentificationEvidenceField encodes record under the fixed evidence key.
func IdentificationEvidenceField(record *IdentificationRecord) (EvidenceField, error) {
	encoded, err := record.MarshalBinary()
	if err != nil {
		return EvidenceField{}, err
	}
	return EvidenceField{Key: IdentificationRecordEvidenceKey, Value: encoded}, nil
}
