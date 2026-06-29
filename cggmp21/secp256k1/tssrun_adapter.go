package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*PresignSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*RefreshSession)(nil)
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

// Handle validates and applies one inbound presign envelope.
func (s *PresignSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandlePresignMessage(in)
}

// Completed reports whether the presign session has produced a presign record.
func (s *PresignSession) Completed() bool {
	_, ok := s.Presign()
	return ok
}

// Handle validates and applies one inbound online signing envelope.
func (s *SignSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandleSignMessage(in)
}

// Completed reports whether the signing session has produced a signature.
func (s *SignSession) Completed() bool {
	_, ok := s.Signature()
	return ok
}

// Handle validates and applies one inbound refresh envelope.
func (s *RefreshSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandleRefreshMessage(in)
}

// Completed reports whether the refresh session has produced a key share.
func (s *RefreshSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}

// Handle validates and applies one inbound reshare envelope.
func (s *ReshareSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.HandleReshareMessage(in)
}

// Completed reports whether the reshare session has produced a key share.
func (s *ReshareSession) Completed() bool {
	_, ok := s.KeyShare()
	return ok
}
