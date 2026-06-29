package ed25519

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
)

// Handle validates and applies one inbound keygen envelope.
func (s *KeygenSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandleKeygenMessage(in)
}

// Completed reports whether the keygen session has produced a confirmed share.
func (s *KeygenSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Handle validates and applies one inbound signing envelope.
func (s *SignSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandleSignMessage(in)
}

// Completed reports whether the signing session has produced a signature.
func (s *SignSession) Completed() bool {
	_, ok := s.Signature()
	return ok
}

// Handle validates and applies one inbound refresh or reshare envelope.
func (s *ReshareSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandleReshareMessage(in)
}

// Completed reports whether the refresh or reshare session has produced a key share.
func (s *ReshareSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}
