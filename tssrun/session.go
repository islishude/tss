package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/islishude/tss"
)

// SessionState is the public lifecycle state of one local protocol session.
type SessionState uint8

const (
	// SessionStarting means registration is waiting for its durable start decision.
	SessionStarting SessionState = iota
	// SessionActive means the protocol may accept inbound messages.
	SessionActive
	// SessionCommitPending means protocol work is complete but an exact durable
	// effect still requires reconciliation.
	SessionCommitPending
	// SessionSucceeded means the protocol and its required durable effect succeeded.
	SessionSucceeded
	// SessionAborted means the protocol reached an authoritative terminal failure.
	SessionAborted
	// SessionClosePending means local secrets were cleared but durable abort or
	// retirement still requires an exact retry.
	SessionClosePending
	// SessionClosed means cleanup completed and the session accepts no further use.
	SessionClosed
)

// Terminal reports whether state is an authoritative protocol terminal state.
func (s SessionState) Terminal() bool {
	return s == SessionSucceeded || s == SessionAborted || s == SessionClosed
}

// SessionDescriptor binds a local protocol session to canonical run metadata.
type SessionDescriptor struct {
	Protocol   tss.ProtocolID
	Kind       RunKind
	SessionID  tss.SessionID
	Party      tss.PartyID
	PlanDigest []byte
}

// Clone returns an independent descriptor copy.
func (d SessionDescriptor) Clone() SessionDescriptor {
	d.PlanDigest = bytes.Clone(d.PlanDigest)
	return d
}

// Validate checks the complete session descriptor.
func (d SessionDescriptor) Validate() error {
	if d.Protocol == "" || !validLeaseRunKind(d.Kind) || !d.SessionID.Valid() || d.Party == tss.BroadcastPartyId || len(d.PlanDigest) != sha256.Size {
		return ErrInvalidSessionKey
	}
	return nil
}

// Equal reports whether two descriptors bind the same local run.
func (d SessionDescriptor) Equal(other SessionDescriptor) bool {
	return d.Protocol == other.Protocol && d.Kind == other.Kind && d.SessionID == other.SessionID && d.Party == other.Party && bytes.Equal(d.PlanDigest, other.PlanDigest)
}

// ProtocolSession is the uniform, context-aware data-plane surface implemented
// by local protocol sessions.
type ProtocolSession interface {
	Descriptor() SessionDescriptor
	Handle(context.Context, tss.InboundEnvelope) ([]tss.Envelope, error)
	Status() SessionState
	Abort(context.Context, string) error
	Close(context.Context) error
}

// HandlerFunc handles one inbound envelope for a session adapter.
type HandlerFunc func(context.Context, tss.InboundEnvelope) ([]tss.Envelope, error)

// SessionAdapter adapts caller-owned protocol handlers to ProtocolSession.
type SessionAdapter struct {
	DescriptorValue SessionDescriptor
	HandleFunc      HandlerFunc
	StatusFunc      func() SessionState
	AbortFunc       func(context.Context, string) error
	CloseFunc       func(context.Context) error
}

// Descriptor returns the adapter's immutable run binding.
func (s SessionAdapter) Descriptor() SessionDescriptor { return s.DescriptorValue.Clone() }

// Handle calls the configured handler.
func (s SessionAdapter) Handle(ctx context.Context, in tss.InboundEnvelope) ([]tss.Envelope, error) {
	if s.HandleFunc == nil {
		return nil, ErrInvalidSessionKey
	}
	if ctx == nil {
		return nil, errors.New("tssrun: nil session handle context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.HandleFunc(ctx, in)
}

// Status returns the adapted session state.
func (s SessionAdapter) Status() SessionState {
	if s.StatusFunc == nil {
		return SessionActive
	}
	return s.StatusFunc()
}

// Abort requests authoritative terminal abort of the adapted session.
func (s SessionAdapter) Abort(ctx context.Context, reason string) error {
	if s.AbortFunc == nil {
		return errors.New("tssrun: session abort is unsupported")
	}
	return s.AbortFunc(ctx, reason)
}

// Close releases adapted session state after any durable disposition is known.
func (s SessionAdapter) Close(ctx context.Context) error {
	if s.CloseFunc == nil {
		return errors.New("tssrun: session close is unsupported")
	}
	return s.CloseFunc(ctx)
}
