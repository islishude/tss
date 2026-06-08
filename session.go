package tss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
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
	return slices.Clone(id[:])
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

// Valid reports whether the session identifier is non-zero.
func (id SessionID) Valid() bool {
	return id != (SessionID{})
}
