package ed25519

import "github.com/islishude/tss/tssrun"

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
)

// Completed reports whether the keygen session has produced a confirmed share.
func (s *KeygenSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Completed reports whether the signing session has produced a signature.
func (s *SignSession) Completed() bool {
	_, ok := s.Signature()
	return ok
}

// Completed reports whether the refresh or reshare session has produced a key share.
func (s *ReshareSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}
