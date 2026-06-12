package ed25519

import (
	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
)

// Destroy clears local secret material retained by the keygen session.
func (s *KeygenSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abort()
	if s.keyShare != nil {
		s.keyShare.Destroy()
	}
}

// Destroy clears local nonces and partial signatures retained by the signing session.
func (s *SignSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abort()
}

func (s *SignSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.clearNonceBytes()
	if s.deltaScalar != nil {
		s.deltaScalar.Set(fed.NewScalar())
	}
	clearScalarMap(s.partials)
	s.partialEnvelopes = nil
	clear(s.message)
	s.message = nil
	clear(s.verifyKey)
	s.verifyKey = nil
	clear(s.signature)
	s.signature = nil
}

// Destroy clears local reshare material retained by the reshare session.
func (s *ReshareSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abort()
	if s.newShare != nil {
		s.newShare.Destroy()
	}
	s.newShare = nil
}

func (s *ReshareSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.clearSensitive()
}

func (s *KeygenSession) clearIntermediateSecrets() {
	if s == nil {
		return
	}
	clearScalarMap(s.shares)
	clearScalars(s.ownPoly)
	clearEnvelopePayloads(s.ownMessages)
	for _, cc := range s.chainCodes {
		clear(cc)
	}
	s.chainCodes = nil
	s.ownPoly = nil
	s.ownMessages = nil
}

func clearScalars(xs []*fed.Scalar) {
	for i := range xs {
		if xs[i] != nil {
			xs[i].Set(fed.NewScalar())
		}
	}
}

func clearScalarMap(xs map[tss.PartyID]*fed.Scalar) {
	for id := range xs {
		if xs[id] != nil {
			xs[id].Set(fed.NewScalar())
		}
		delete(xs, id)
	}
}

func clearEnvelopePayloads(envelopes []tss.Envelope) {
	for i := range envelopes {
		clear(envelopes[i].Payload)
		envelopes[i].Payload = nil
	}
}
