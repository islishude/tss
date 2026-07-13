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

// Identifying reports whether keygen is in an extra identification round.
// Keygen deviations are verified and attributed in their originating round.
func (s *KeygenSession) Identifying() bool { return false }

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

// Identifying reports whether Figure 9 attributable abort is active.
func (s *PresignSession) Identifying() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identifying
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

// Identifying is always false: Figure 10 attributes an invalid partial directly.
func (s *SignSession) Identifying() bool { return false }

// Completed reports whether the refresh lifecycle reached terminal success.
func (s *RefreshSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Identifying reports whether refresh is in an extra identification round.
// Refresh deviations are verified and attributed in their originating round.
func (s *RefreshSession) Identifying() bool { return false }

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

// Identifying reports whether reshare is in an extra identification round.
// Reshare deviations are verified and attributed in their originating round.
func (s *ReshareSession) Identifying() bool { return false }
