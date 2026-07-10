package secp256k1

import "github.com/islishude/tss/tssrun"

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*PresignSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*RefreshSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
)

// Completed reports whether the keygen session has produced a confirmed share.
func (s *KeygenSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Completed reports whether the presign session has produced a presign record.
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
	_, ok := s.Signature()
	return ok
}

// Completed reports whether the refresh session has produced a key share.
func (s *RefreshSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Completed reports whether the reshare session has produced a key share.
func (s *ReshareSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}
