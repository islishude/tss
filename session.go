package tss

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	sessionIDSize    = 32
	sessionIDHexSize = sessionIDSize * 2
)

// SessionID is a 32-byte nonce that separates independent protocol executions.
type SessionID [sessionIDSize]byte

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
	if len(in) != sessionIDSize {
		return SessionID{}, fmt.Errorf("session id: expected %d bytes, got %d", sessionIDSize, len(in))
	}

	var id SessionID
	copy(id[:], in)
	return id, nil
}

// Bytes returns a copy of the session identifier bytes.
func (id SessionID) Bytes() []byte {
	return bytes.Clone(id[:])
}

// String returns the hex encoding of the session identifier.
func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalText encodes the session identifier as hex text.
func (id SessionID) MarshalText() ([]byte, error) {
	out := make([]byte, sessionIDHexSize)
	hex.Encode(out, id[:])
	return out, nil
}

// UnmarshalText decodes a hex session identifier.
func (id *SessionID) UnmarshalText(text []byte) error {
	if id == nil {
		return errors.New("session id: nil receiver")
	}
	if len(text) != sessionIDHexSize {
		return fmt.Errorf("session id: invalid hex length: expected %d, got %d", sessionIDHexSize, len(text))
	}

	var decoded SessionID
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return fmt.Errorf("session id: invalid hex: %w", err)
	}

	*id = decoded
	return nil
}

// Valid reports whether the session identifier is non-zero.
func (id SessionID) Valid() bool {
	return id != SessionID{}
}
