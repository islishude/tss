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

// Identifying reports whether keygen is in an extra identification round.
// Keygen deviations are verified and attributed in their originating round.
func (s *KeygenSession) Identifying() bool { return false }

// Completed reports whether the presign session has produced a presign record.
func (s *PresignSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed && !s.identifying
}

// Identifying reports whether conditional presign identification is active.
func (s *PresignSession) Identifying() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identifying && !s.completed && !s.aborted
}

// Completed reports whether the signing session has produced a signature.
func (s *SignSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed && !s.identifying
}

// Identifying reports whether conditional online-sign identification is active.
func (s *SignSession) Identifying() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identifying && !s.completed && !s.aborted
}

// Completed reports whether the refresh session has produced a key share.
func (s *RefreshSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Identifying reports whether refresh is in an extra identification round.
// Refresh deviations are verified and attributed in their originating round.
func (s *RefreshSession) Identifying() bool { return false }

// Completed reports whether the reshare session has produced a key share.
func (s *ReshareSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Identifying reports whether reshare is in an extra identification round.
// Reshare deviations are verified and attributed in their originating round.
func (s *ReshareSession) Identifying() bool { return false }
