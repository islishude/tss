package ed25519

import (
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
func (s *RefreshSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	if s == nil || s.reshare == nil {
		return nil, errors.New("nil refresh session")
	}
	return s.reshare.Handle(in)
}

// KeyShare returns an independently owned refreshed key share after every
// target-holder confirmation has been verified.
func (s *RefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil || s.reshare == nil {
		return nil, false
	}
	return s.reshare.KeyShare()
}

// Completed reports whether the refresh session is terminally complete.
func (s *RefreshSession) Completed() bool {
	if s == nil || s.reshare == nil {
		return false
	}
	return s.reshare.Completed()
}

// Destroy clears local material retained by the refresh session.
func (s *RefreshSession) Destroy() {
	if s == nil || s.reshare == nil {
		return
	}
	s.reshare.Destroy()
}
