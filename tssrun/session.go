package tssrun

import "github.com/islishude/tss"

// ProtocolSession is the uniform data-plane surface implemented by local
// protocol sessions.
type ProtocolSession interface {
	Handle(tss.InboundEnvelope) ([]tss.Envelope, error)
	Completed() bool
	Destroy()
}

// HandlerFunc handles one inbound envelope for a session adapter.
type HandlerFunc func(tss.InboundEnvelope) ([]tss.Envelope, error)

// SessionAdapter adapts caller-owned protocol handlers to ProtocolSession.
type SessionAdapter struct {
	HandleFunc    HandlerFunc
	CompletedFunc func() bool
	DestroyFunc   func()
}

// Handle calls the configured handler.
func (s SessionAdapter) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	if s.HandleFunc == nil {
		return nil, ErrInvalidSessionKey
	}
	return s.HandleFunc(in)
}

// Completed reports whether the adapted session is terminally complete.
func (s SessionAdapter) Completed() bool {
	if s.CompletedFunc == nil {
		return false
	}
	return s.CompletedFunc()
}

// Destroy releases session-owned material through the configured callback.
func (s SessionAdapter) Destroy() {
	if s.DestroyFunc != nil {
		s.DestroyFunc()
	}
}
