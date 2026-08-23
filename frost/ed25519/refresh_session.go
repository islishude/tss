package ed25519

import (
	"context"
	"errors"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

var (
	_ tss.RefreshSession[*KeyShare] = (*RefreshSession)(nil)
	_ tssrun.ProtocolSession        = (*RefreshSession)(nil)
)

// RefreshSession is the FROST same-committee proactive-refresh session.
// It intentionally exposes a distinct public type while delegating the shared
// refresh/reshare state machine to an internal ReshareSession.
type RefreshSession struct {
	reshare *ReshareSession
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *RefreshSession) Guard() *tss.EnvelopeGuard {
	if s == nil || s.reshare == nil {
		return nil
	}
	return s.reshare.Guard()
}

// Handle validates and applies one refresh envelope.
func (s *RefreshSession) Handle(ctx context.Context, in tss.InboundEnvelope) ([]tss.Envelope, error) {
	if s == nil || s.reshare == nil {
		return nil, errors.New("nil refresh session")
	}
	return s.reshare.Handle(ctx, in)
}

// KeyShare returns an independently owned refreshed key share after every
// target-holder confirmation has been verified.
func (s *RefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil || s.reshare == nil {
		return nil, false
	}
	return s.reshare.KeyShare()
}

// Descriptor returns the wrapped refresh run binding.
func (s *RefreshSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil || s.reshare == nil {
		return tssrun.SessionDescriptor{}
	}
	return s.reshare.Descriptor()
}

// Status returns the wrapped refresh lifecycle state.
func (s *RefreshSession) Status() tssrun.SessionState {
	if s == nil || s.reshare == nil {
		return tssrun.SessionClosed
	}
	return s.reshare.Status()
}

// Abort terminally aborts the wrapped refresh run.
func (s *RefreshSession) Abort(ctx context.Context, reason string) error {
	if s == nil || s.reshare == nil {
		return nil
	}
	return s.reshare.Abort(ctx, reason)
}

// Close clears the wrapped refresh session.
func (s *RefreshSession) Close(ctx context.Context) error {
	if s == nil || s.reshare == nil {
		return nil
	}
	return s.reshare.Close(ctx)
}
