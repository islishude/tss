package ed25519

import "github.com/islishude/tss/tssrun"

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
)

// Completed reports whether the keygen session is terminally complete.
func (s *KeygenSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Completed reports whether the signing session is terminally complete.
func (s *SignSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Completed reports whether the refresh or reshare session is terminally complete.
func (s *ReshareSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}
