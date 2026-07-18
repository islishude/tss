package secp256k1

import "github.com/islishude/tss/tssrun"

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*PresignSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*RefreshSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
)

// Completed reports whether the keygen lifecycle reached terminal success.
func (s *KeygenSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Completed reports whether the presign session has durably committed its
// presign and exposed the corresponding public descriptor.
func (s *PresignSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Completed reports whether the signing session has produced a signature.
func (s *SignSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Completed reports whether the refresh lifecycle reached terminal success.
func (s *RefreshSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Completed reports whether the reshare lifecycle reached terminal success.
// Dealer-only participants complete without producing a replacement key share.
func (s *ReshareSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}
