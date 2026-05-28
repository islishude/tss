package tss

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	// EvidenceKindFrostPartialSignature marks an invalid FROST partial signature.
	EvidenceKindFrostPartialSignature EvidenceKind = "frost_partial_signature"
	// EvidenceKindFrostAggregateSignature marks a failed FROST aggregate Ed25519 signature.
	EvidenceKindFrostAggregateSignature EvidenceKind = "frost_aggregate_signature"
)

// EvidenceField carries one public input or public-input hash for blame evidence.
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
		TranscriptHash: slices.Clone(env.TranscriptHash),
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
	if err := normalizeEvidenceFields(e.PublicInputs); err != nil {
		return err
	}
	return nil
}

// MarshalBinary returns deterministic JSON for public blame evidence.
func (e *BlameEvidence) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	canonical := *e
	canonical.PayloadHash = slices.Clone(e.PayloadHash)
	canonical.TranscriptHash = slices.Clone(e.TranscriptHash)
	canonical.PublicInputs = cloneEvidenceFields(e.PublicInputs)
	if err := normalizeEvidenceFields(canonical.PublicInputs); err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

// UnmarshalBlameEvidence decodes and validates public blame evidence.
func UnmarshalBlameEvidence(in []byte) (*BlameEvidence, error) {
	var evidence BlameEvidence
	if err := json.Unmarshal(in, &evidence); err != nil {
		return nil, err
	}
	evidence.PayloadHash = slices.Clone(evidence.PayloadHash)
	evidence.TranscriptHash = slices.Clone(evidence.TranscriptHash)
	evidence.PublicInputs = cloneEvidenceFields(evidence.PublicInputs)
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	if err := normalizeEvidenceFields(evidence.PublicInputs); err != nil {
		return nil, err
	}
	return &evidence, nil
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

func cloneEvidenceFields(in []EvidenceField) []EvidenceField {
	if len(in) == 0 {
		return nil
	}
	out := make([]EvidenceField, len(in))
	for i, field := range in {
		out[i] = EvidenceField{Key: field.Key, Value: slices.Clone(field.Value)}
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
