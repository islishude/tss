package tssrun

import (
	"context"
	"slices"
	"sync"

	"github.com/islishude/tss"
)

const (
	defaultUnknownEnvelopeMaxEntries    = 4096
	defaultUnknownEnvelopeMaxPerSession = 256
)

// RejectUnknownSession is the fail-closed default unknown-session policy.
type RejectUnknownSession struct{}

// OnUnknownEnvelope rejects the inbound envelope.
func (RejectUnknownSession) OnUnknownEnvelope(context.Context, tss.InboundEnvelope) error {
	return ErrUnknownSession
}

// DurableBufferUnknownSession stores unknown-session envelopes for later
// revalidation by the caller after a run is accepted and a session is registered.
type DurableBufferUnknownSession struct {
	Store UnknownEnvelopeStore
}

// OnUnknownEnvelope stores the envelope without delivering it to a session.
func (p DurableBufferUnknownSession) OnUnknownEnvelope(ctx context.Context, in tss.InboundEnvelope) error {
	if p.Store == nil {
		return ErrUnknownSession
	}
	return p.Store.PutUnknown(ctx, in)
}

// UnknownEnvelopeStore stores opened inbound envelopes that could not yet be routed.
type UnknownEnvelopeStore interface {
	PutUnknown(ctx context.Context, in tss.InboundEnvelope) error
	LoadBySession(ctx context.Context, protocol tss.ProtocolID, sessionID tss.SessionID) ([]tss.InboundEnvelope, error)
	DeleteBySession(ctx context.Context, protocol tss.ProtocolID, sessionID tss.SessionID) error
}

// MemoryUnknownEnvelopeStore is an in-memory reference unknown-envelope store.
type MemoryUnknownEnvelopeStore struct {
	mu        sync.Mutex
	envelopes map[unknownIndex][]tss.InboundEnvelope
	total     int

	maxEntries    int
	maxPerSession int
}

type unknownIndex struct {
	protocol  tss.ProtocolID
	sessionID tss.SessionID
}

// NewMemoryUnknownEnvelopeStore returns an empty unknown-envelope store.
func NewMemoryUnknownEnvelopeStore() *MemoryUnknownEnvelopeStore {
	return NewBoundedMemoryUnknownEnvelopeStore(defaultUnknownEnvelopeMaxEntries, defaultUnknownEnvelopeMaxPerSession)
}

// NewBoundedMemoryUnknownEnvelopeStore returns an empty unknown-envelope store
// with explicit global and per-session entry limits. Non-positive limits use
// the default quota.
func NewBoundedMemoryUnknownEnvelopeStore(maxEntries, maxPerSession int) *MemoryUnknownEnvelopeStore {
	if maxEntries <= 0 {
		maxEntries = defaultUnknownEnvelopeMaxEntries
	}
	if maxPerSession <= 0 {
		maxPerSession = defaultUnknownEnvelopeMaxPerSession
	}
	if maxPerSession > maxEntries {
		maxPerSession = maxEntries
	}
	return &MemoryUnknownEnvelopeStore{
		envelopes:     make(map[unknownIndex][]tss.InboundEnvelope),
		maxEntries:    maxEntries,
		maxPerSession: maxPerSession,
	}
}

// PutUnknown stores an opened inbound envelope for later revalidation.
func (s *MemoryUnknownEnvelopeStore) PutUnknown(ctx context.Context, in tss.InboundEnvelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	idx := unknownIndex{protocol: in.Protocol(), sessionID: in.SessionID()}
	if idx.protocol == "" || !idx.sessionID.Valid() {
		return ErrInvalidSessionKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.envelopes == nil {
		s.envelopes = make(map[unknownIndex][]tss.InboundEnvelope)
	}
	maxEntries, maxPerSession := s.limits()
	if len(s.envelopes[idx]) >= maxPerSession || s.total >= maxEntries {
		return ErrUnknownSessionBufferFull
	}
	s.envelopes[idx] = append(s.envelopes[idx], in)
	s.total++
	return nil
}

// LoadBySession returns buffered envelopes for a protocol/session.
func (s *MemoryUnknownEnvelopeStore) LoadBySession(ctx context.Context, protocol tss.ProtocolID, sessionID tss.SessionID) ([]tss.InboundEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if protocol == "" || !sessionID.Valid() {
		return nil, ErrInvalidSessionKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	buffered := s.envelopes[unknownIndex{protocol: protocol, sessionID: sessionID}]
	return slices.Clone(buffered), nil
}

// DeleteBySession deletes buffered envelopes for a protocol/session.
func (s *MemoryUnknownEnvelopeStore) DeleteBySession(ctx context.Context, protocol tss.ProtocolID, sessionID tss.SessionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if protocol == "" || !sessionID.Valid() {
		return ErrInvalidSessionKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := unknownIndex{protocol: protocol, sessionID: sessionID}
	if buffered, ok := s.envelopes[idx]; ok {
		s.total -= len(buffered)
		if s.total < 0 {
			s.total = 0
		}
		delete(s.envelopes, idx)
	}
	return nil
}

func (s *MemoryUnknownEnvelopeStore) limits() (int, int) {
	maxEntries := s.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultUnknownEnvelopeMaxEntries
	}
	maxPerSession := s.maxPerSession
	if maxPerSession <= 0 {
		maxPerSession = defaultUnknownEnvelopeMaxPerSession
	}
	if maxPerSession > maxEntries {
		maxPerSession = maxEntries
	}
	return maxEntries, maxPerSession
}
