package tssrun

import (
	"context"
	"sync"

	"github.com/islishude/tss"
)

// SessionKey routes one local protocol session.
type SessionKey struct {
	Protocol  tss.ProtocolID
	SessionID tss.SessionID
	Party     tss.PartyID
}

// SessionRegistry stores active local sessions by protocol/session/party.
type SessionRegistry interface {
	Put(ctx context.Context, key SessionKey, session ProtocolSession) error
	Lookup(ctx context.Context, key SessionKey) (ProtocolSession, bool, error)
	Retire(ctx context.Context, key SessionKey) error
}

// MemorySessionRegistry is a mutex-protected reference SessionRegistry.
type MemorySessionRegistry struct {
	mu       sync.Mutex
	sessions map[SessionKey]ProtocolSession
}

// NewMemorySessionRegistry returns an empty in-memory session registry.
func NewMemorySessionRegistry() *MemorySessionRegistry {
	return &MemorySessionRegistry{sessions: make(map[SessionKey]ProtocolSession)}
}

// Put registers an active session and rejects duplicate keys.
func (r *MemorySessionRegistry) Put(ctx context.Context, key SessionKey, session ProtocolSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSessionKey(key); err != nil {
		return err
	}
	if session == nil {
		return ErrInvalidSessionKey
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[key]; ok {
		return ErrSessionConflict
	}
	r.sessions[key] = session
	return nil
}

// Lookup returns the active session for key, if present.
func (r *MemorySessionRegistry) Lookup(ctx context.Context, key SessionKey) (ProtocolSession, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := validateSessionKey(key); err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[key]
	return session, ok, nil
}

// Retire removes a session key. Retiring a missing key is idempotent.
func (r *MemorySessionRegistry) Retire(ctx context.Context, key SessionKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSessionKey(key); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, key)
	return nil
}

func validateSessionKey(key SessionKey) error {
	if key.Protocol == "" || !key.SessionID.Valid() || key.Party == 0 {
		return ErrInvalidSessionKey
	}
	return nil
}
