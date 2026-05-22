package tss

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

type EvidenceKind string

const (
	EvidenceKindKeygenCommitment EvidenceKind = "keygen_commitment"
	EvidenceKindKeygenPaillier   EvidenceKind = "keygen_paillier"
	EvidenceKindKeygenShare      EvidenceKind = "keygen_share"
	EvidenceKindPresignRound1    EvidenceKind = "presign_round1"
	EvidenceKindPresignRound2    EvidenceKind = "presign_round2"
	EvidenceKindPresignRound3    EvidenceKind = "presign_round3"
	EvidenceKindSignPartial      EvidenceKind = "sign_partial"
	EvidenceKindAggregateSign    EvidenceKind = "aggregate_signature"
)

type EvidenceField struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

// BlameEvidence is intentionally public-only. Confidential protocol messages
// should be represented by hashes or other public inputs, not by plaintext.
type BlameEvidence struct {
	Version        uint16          `json:"version"`
	Protocol       string          `json:"protocol"`
	SessionID      SessionID       `json:"session_id"`
	Round          uint8           `json:"round"`
	From           PartyID         `json:"from"`
	To             PartyID         `json:"to,omitempty"`
	PayloadType    string          `json:"payload_type"`
	PayloadHash    []byte          `json:"payload_hash"`
	TranscriptHash []byte          `json:"transcript_hash,omitempty"`
	Kind           EvidenceKind    `json:"kind"`
	Reason         string          `json:"reason"`
	PublicInputs   []EvidenceField `json:"public_inputs,omitempty"`
}

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
		TranscriptHash: CloneBytes(env.TranscriptHash),
		Kind:           kind,
		Reason:         reason,
		PublicInputs:   cloneEvidenceFields(inputs),
	}
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	return evidence, nil
}

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
	if err := normalizeEvidenceFields(e.PublicInputs); err != nil {
		return err
	}
	return nil
}

func (e *BlameEvidence) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	canonical := *e
	canonical.PayloadHash = CloneBytes(e.PayloadHash)
	canonical.TranscriptHash = CloneBytes(e.TranscriptHash)
	canonical.PublicInputs = cloneEvidenceFields(e.PublicInputs)
	if err := normalizeEvidenceFields(canonical.PublicInputs); err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func UnmarshalBlameEvidence(in []byte) (*BlameEvidence, error) {
	var evidence BlameEvidence
	if err := json.Unmarshal(in, &evidence); err != nil {
		return nil, err
	}
	evidence.PayloadHash = CloneBytes(evidence.PayloadHash)
	evidence.TranscriptHash = CloneBytes(evidence.TranscriptHash)
	evidence.PublicInputs = cloneEvidenceFields(evidence.PublicInputs)
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	if err := normalizeEvidenceFields(evidence.PublicInputs); err != nil {
		return nil, err
	}
	return &evidence, nil
}

func (e *BlameEvidence) Hash() ([]byte, error) {
	encoded, err := e.MarshalBinary()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func (e *BlameEvidence) Field(key string) ([]byte, bool) {
	if e == nil {
		return nil, false
	}
	for _, field := range e.PublicInputs {
		if field.Key == key {
			return CloneBytes(field.Value), true
		}
	}
	return nil, false
}

func cloneEvidenceFields(in []EvidenceField) []EvidenceField {
	if len(in) == 0 {
		return nil
	}
	out := make([]EvidenceField, len(in))
	for i, field := range in {
		out[i] = EvidenceField{Key: field.Key, Value: CloneBytes(field.Value)}
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
