package ed25519

import (
	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
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
	s.clearNonceScalars()
	if s.deltaScalar != nil {
		s.deltaScalar.Set(fed.NewScalar())
	}
	if s.derivation != nil {
		s.derivation.Destroy()
		s.derivation = nil
	}
	clearScalarMap(s.partials)
	s.partialEnvelopes = nil
	clearScalarMap(s.pendingPartials)
	s.pendingPartials = nil
	s.pendingEnvelopes = nil
	clear(s.message)
	s.message = nil
	clear(s.signature)
	s.signature = nil
}

func (s *SignSession) clearCompletedSigningState() {
	if s == nil {
		return
	}
	s.clearNonceScalars()
	clearScalarMap(s.partials)
	s.partials = nil
	s.partialEnvelopes = nil
	clearScalarMap(s.pendingPartials)
	s.pendingPartials = nil
	s.pendingEnvelopes = nil
	clear(s.message)
	s.message = nil
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
	if s.pendingShare != nil {
		s.pendingShare.Destroy()
		s.pendingShare = nil
	}
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

func clearSecretScalarMap(xs map[tss.PartyID]*secret.Scalar) {
	for id := range xs {
		if xs[id] != nil {
			xs[id].Destroy()
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
