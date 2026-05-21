package tss

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

const Version = 1

type PartyID uint32

type Algorithm string

const (
	AlgorithmGG20Secp256k1 Algorithm = "gg20-secp256k1"
	AlgorithmFROSTEd25519  Algorithm = "frost-ed25519"
)

type SessionID [32]byte

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

func SessionIDFromBytes(in []byte) (SessionID, error) {
	var id SessionID
	if len(in) != len(id) {
		return id, fmt.Errorf("session id must be %d bytes", len(id))
	}
	copy(id[:], in)
	return id, nil
}

func (id SessionID) Bytes() []byte {
	out := make([]byte, len(id))
	copy(out, id[:])
	return out
}

func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

func (id SessionID) MarshalText() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(id)))
	hex.Encode(out, id[:])
	return out, nil
}

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

type ThresholdConfig struct {
	Threshold int
	Parties   []PartyID
	Self      PartyID
	SessionID SessionID
	Rand      io.Reader `json:"-"`
}

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

func (c ThresholdConfig) SortedParties() []PartyID {
	out := append([]PartyID(nil), c.Parties...)
	slices.Sort(out)
	return out
}

func (c ThresholdConfig) Reader() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

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

func (e Envelope) MarshalBinary() ([]byte, error) {
	return json.Marshal(e)
}

func (e *Envelope) UnmarshalBinary(in []byte) error {
	return json.Unmarshal(in, e)
}

func (e Envelope) DomainSeparatedHash() []byte {
	h := sha256.New()
	// The protocol/version/session/round tuple keeps transcripts from one
	// algorithm or session from being replayed into another.
	h.Write([]byte("github.com/islishude/tss/envelope/v1"))
	h.Write([]byte{0})
	h.Write([]byte(e.Protocol))
	h.Write([]byte{0, byte(e.Version >> 8), byte(e.Version), e.Round})
	h.Write(e.SessionID[:])
	writeUint32(h, uint32(e.From))
	writeUint32(h, uint32(e.To))
	h.Write([]byte(e.PayloadType))
	h.Write([]byte{0})
	h.Write(e.Payload)
	return h.Sum(nil)
}

func (e Envelope) WithTranscriptHash() Envelope {
	e.TranscriptHash = e.DomainSeparatedHash()
	return e
}

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
	if len(e.TranscriptHash) > 0 {
		want := e.DomainSeparatedHash()
		if string(want) != string(e.TranscriptHash) {
			return errors.New("transcript hash mismatch")
		}
	}
	if len(parties) > 0 && !ContainsParty(parties, e.From) {
		return fmt.Errorf("sender %d is not a participant", e.From)
	}
	return nil
}

type KeyShare interface {
	Algorithm() Algorithm
	PartyID() PartyID
	PublicKeyBytes() []byte
	MarshalBinary() ([]byte, error)
	Destroy()
}

type Signature struct {
	Algorithm Algorithm `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	Data      []byte    `json:"data"`
	R         []byte    `json:"r,omitempty"`
	S         []byte    `json:"s,omitempty"`
}

type Blame struct {
	Reason   string    `json:"reason"`
	Parties  []PartyID `json:"parties"`
	Evidence []byte    `json:"evidence,omitempty"`
}

func ContainsParty(parties []PartyID, id PartyID) bool {
	return slices.Contains(parties, id)
}

func SortParties(parties []PartyID) []PartyID {
	out := append([]PartyID(nil), parties...)
	slices.Sort(out)
	return out
}

func writeUint32(w io.Writer, v uint32) {
	_, _ = w.Write([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
