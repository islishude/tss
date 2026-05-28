package tss

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/islishude/tss/internal/wire"
)

// Version is the library wire/protocol version used by current messages.
const Version = 1

const envelopeHashLabel = "github.com/islishude/tss/envelope/v1"

const envelopeWireType = "tss.envelope"

const (
	envelopeFieldProtocol uint16 = iota + 1
	envelopeFieldVersion
	envelopeFieldSessionID
	envelopeFieldRound
	envelopeFieldFrom
	envelopeFieldTo
	envelopeFieldPayloadType
	envelopeFieldPayload
	envelopeFieldTranscriptHash
	envelopeFieldConfidentialRequired
)

// PartyID identifies one protocol participant; zero is reserved as "unset".
type PartyID uint32

// Algorithm names a threshold signature algorithm implemented by this module.
type Algorithm string

const (
	// AlgorithmCGGMP21Secp256k1 identifies the CGGMP21-style threshold ECDSA package.
	AlgorithmCGGMP21Secp256k1 Algorithm = "cggmp21-secp256k1"
	// AlgorithmFROSTEd25519 identifies the FROST-style threshold Ed25519 package.
	AlgorithmFROSTEd25519 Algorithm = "frost-ed25519"
)

// SessionID is a 32-byte nonce that separates independent protocol executions.
type SessionID [32]byte

// NewSessionID returns a random session identifier from reader or crypto/rand.
func NewSessionID(reader io.Reader) (SessionID, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var id SessionID
	if _, err := io.ReadFull(reader, id[:]); err != nil {
		return SessionID{}, err
	}
	return id, nil
}

// SessionIDFromBytes parses a 32-byte session identifier.
func SessionIDFromBytes(in []byte) (SessionID, error) {
	var id SessionID
	if len(in) != len(id) {
		return id, fmt.Errorf("session id must be %d bytes", len(id))
	}
	copy(id[:], in)
	return id, nil
}

// Bytes returns a copy of the session identifier bytes.
func (id SessionID) Bytes() []byte {
	out := make([]byte, len(id))
	copy(out, id[:])
	return out
}

// String returns the hex encoding of the session identifier.
func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalText encodes the session identifier as hex text.
func (id SessionID) MarshalText() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(id)))
	hex.Encode(out, id[:])
	return out, nil
}

// UnmarshalText decodes a hex session identifier.
func (id *SessionID) UnmarshalText(text []byte) error {
	raw, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	parsed, err := SessionIDFromBytes(raw)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// ThresholdConfig contains local participant configuration for a protocol run.
type ThresholdConfig struct {
	Threshold    int
	Parties      []PartyID
	Self         PartyID
	SessionID    SessionID
	Rand         io.Reader       `json:"-"`
	Context      context.Context `json:"-"`
	RoundTimeout time.Duration   `json:"-"`
	Log          Logger          `json:"-"`
}

// Ctx returns the configuration context or context.Background when unset.
func (c ThresholdConfig) Ctx() context.Context {
	if c.Context != nil {
		return c.Context
	}
	return context.Background()
}

// Validate checks threshold, party-set, and local-party invariants.
func (c ThresholdConfig) Validate() error {
	if c.Threshold <= 0 {
		return errors.New("threshold must be positive")
	}
	if len(c.Parties) == 0 {
		return errors.New("parties must not be empty")
	}
	if c.Threshold > len(c.Parties) {
		return errors.New("threshold exceeds party count")
	}
	seen := make(map[PartyID]struct{}, len(c.Parties))
	hasSelf := false
	for _, id := range c.Parties {
		if id == 0 {
			return errors.New("party id 0 is reserved")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate party id %d", id)
		}
		seen[id] = struct{}{}
		if id == c.Self {
			hasSelf = true
		}
	}
	if !hasSelf {
		return errors.New("self must be in parties")
	}
	return nil
}

// SortedParties returns the configured party set in ascending order.
func (c ThresholdConfig) SortedParties() []PartyID {
	out := append([]PartyID(nil), c.Parties...)
	slices.Sort(out)
	return out
}

// Reader returns the configured randomness source or crypto/rand.
func (c ThresholdConfig) Reader() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

// Envelope is a transport-neutral protocol message.
type Envelope struct {
	Protocol             string    `json:"protocol"`
	Version              uint16    `json:"version"`
	SessionID            SessionID `json:"session_id"`
	Round                uint8     `json:"round"`
	From                 PartyID   `json:"from"`
	To                   PartyID   `json:"to,omitempty"` // zero means broadcast
	PayloadType          string    `json:"payload_type"`
	Payload              []byte    `json:"payload"`
	TranscriptHash       []byte    `json:"transcript_hash"`
	ConfidentialRequired bool      `json:"confidential_required,omitempty"` // transport must encrypt/authenticate this envelope
}

// MarshalBinary encodes the envelope using strict canonical TLV wire format.
func (e Envelope) MarshalBinary() ([]byte, error) {
	if e.Protocol == "" {
		return nil, errors.New("envelope protocol is empty")
	}
	if e.Version != Version {
		return nil, fmt.Errorf("unexpected envelope version %d", e.Version)
	}
	if e.PayloadType == "" {
		return nil, errors.New("envelope payload type is empty")
	}
	if len(e.TranscriptHash) != 0 && len(e.TranscriptHash) != sha256.Size {
		return nil, errors.New("invalid envelope transcript hash")
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
		{Tag: envelopeFieldTranscriptHash, Value: wire.NonNilBytes(e.TranscriptHash)},
		{Tag: envelopeFieldConfidentialRequired, Value: wire.Bool(e.ConfidentialRequired)},
	})
}

// UnmarshalBinary decodes a canonical TLV envelope and rejects JSON fallback.
func (e *Envelope) UnmarshalBinary(in []byte) error {
	version, fields, err := wire.Unmarshal(in, envelopeWireType)
	if err != nil {
		return err
	}
	if version != Version {
		return fmt.Errorf("unexpected envelope wire version %d", version)
	}
	protocol, err := wire.Require(fields, envelopeFieldProtocol)
	if err != nil {
		return err
	}
	versionBytes, err := wire.Require(fields, envelopeFieldVersion)
	if err != nil {
		return err
	}
	envVersion, err := wire.DecodeUint16(versionBytes)
	if err != nil {
		return fmt.Errorf("invalid envelope version field: %w", err)
	}
	if envVersion != Version {
		return fmt.Errorf("unexpected envelope version %d", envVersion)
	}
	sessionBytes, err := wire.Require(fields, envelopeFieldSessionID)
	if err != nil {
		return err
	}
	session, err := SessionIDFromBytes(sessionBytes)
	if err != nil {
		return err
	}
	round, err := wire.Require(fields, envelopeFieldRound)
	if err != nil {
		return err
	}
	if len(round) != 1 {
		return errors.New("invalid envelope round")
	}
	fromBytes, err := wire.Require(fields, envelopeFieldFrom)
	if err != nil {
		return err
	}
	from, err := wire.DecodeUint32(fromBytes)
	if err != nil {
		return fmt.Errorf("invalid envelope sender: %w", err)
	}
	toBytes, err := wire.Require(fields, envelopeFieldTo)
	if err != nil {
		return err
	}
	to, err := wire.DecodeUint32(toBytes)
	if err != nil {
		return fmt.Errorf("invalid envelope recipient: %w", err)
	}
	payloadType, err := wire.Require(fields, envelopeFieldPayloadType)
	if err != nil {
		return err
	}
	payload, err := wire.Require(fields, envelopeFieldPayload)
	if err != nil {
		return err
	}
	transcript, err := wire.Require(fields, envelopeFieldTranscriptHash)
	if err != nil {
		return err
	}
	if len(transcript) != 0 && len(transcript) != sha256.Size {
		return errors.New("invalid envelope transcript hash")
	}
	confidentialBytes, err := wire.Require(fields, envelopeFieldConfidentialRequired)
	if err != nil {
		return err
	}
	confidential, err := wire.DecodeBool(confidentialBytes)
	if err != nil {
		return err
	}
	if len(protocol) == 0 {
		return errors.New("envelope protocol is empty")
	}
	if len(payloadType) == 0 {
		return errors.New("envelope payload type is empty")
	}
	*e = Envelope{
		Protocol:             string(protocol),
		Version:              envVersion,
		SessionID:            session,
		Round:                round[0],
		From:                 PartyID(from),
		To:                   PartyID(to),
		PayloadType:          string(payloadType),
		Payload:              payload,
		TranscriptHash:       transcript,
		ConfidentialRequired: confidential,
	}
	return nil
}

// DomainSeparatedHash hashes the public envelope metadata and payload.
func (e Envelope) DomainSeparatedHash() []byte {
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
	return h.Sum(nil)
}

// WithTranscriptHash returns a copy of the envelope with its transcript hash set.
func (e Envelope) WithTranscriptHash() Envelope {
	e.TranscriptHash = e.DomainSeparatedHash()
	return e
}

// ValidateBasic checks envelope metadata before protocol-specific decoding.
func (e Envelope) ValidateBasic(protocol string, session SessionID, parties []PartyID) error {
	// Validate common envelope metadata before protocol-specific decoding. This
	// keeps malformed or cross-session messages from reaching state machines.
	if e.Protocol != protocol {
		return fmt.Errorf("unexpected protocol %q", e.Protocol)
	}
	if e.Version != Version {
		return fmt.Errorf("unexpected version %d", e.Version)
	}
	if e.SessionID != session {
		return errors.New("session mismatch")
	}
	if len(e.TranscriptHash) != sha256.Size {
		return errors.New("missing or invalid envelope transcript hash")
	}
	want := e.DomainSeparatedHash()
	if !slices.Equal(want, e.TranscriptHash) {
		return errors.New("transcript hash mismatch")
	}
	if len(parties) > 0 && !ContainsParty(parties, e.From) {
		return fmt.Errorf("sender %d is not a participant", e.From)
	}
	return nil
}

// KeyShare is the common interface implemented by algorithm-specific shares.
type KeyShare interface {
	Algorithm() Algorithm
	PartyID() PartyID
	PublicKeyBytes() []byte
	MarshalBinary() ([]byte, error)
	Destroy()
}

// Signature is the common transport shape for algorithm-specific signatures.
type Signature struct {
	Algorithm Algorithm `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	Data      []byte    `json:"data"`
	R         []byte    `json:"r,omitempty"`
	S         []byte    `json:"s,omitempty"`
}

// Blame identifies parties and public evidence associated with a protocol failure.
type Blame struct {
	Reason   string    `json:"reason"`
	Parties  []PartyID `json:"parties"`
	Evidence []byte    `json:"evidence,omitempty"`
}

// ContainsParty reports whether id appears in parties.
func ContainsParty(parties []PartyID, id PartyID) bool {
	return slices.Contains(parties, id)
}

// SortParties returns a sorted copy of parties.
func SortParties(parties []PartyID) []PartyID {
	out := append([]PartyID(nil), parties...)
	slices.Sort(out)
	return out
}
