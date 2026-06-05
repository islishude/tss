package ed25519

import (
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// Destroy clears local secret material retained by the keygen session.
func (s *KeygenSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clearScalarMap(s.shares)
	clearScalars(s.ownPoly)
	clearEnvelopePayloads(s.ownMessages)
	for _, cc := range s.chainCodes {
		clear(cc)
	}
	s.chainCodes = nil
	s.ownPoly = nil
	s.ownMessages = nil
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
	// Zero constant-time fiat scalars in place.
	s.d = edcurve.ScalarZero()
	s.e = edcurve.ScalarZero()
	s.deltaScalar = edcurve.ScalarZero()
	for id := range s.partials {
		s.partials[id] = edcurve.ScalarZero()
		delete(s.partials, id)
	}
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
	clearScalarMap(s.shares)
	if s.newShare != nil {
		s.newShare.Destroy()
	}
	s.newShare = nil
}

func clearScalars(xs []edcurve.Scalar) {
	for i := range xs {
		xs[i] = edcurve.ScalarZero()
	}
}

func clearScalarMap(xs map[tss.PartyID]edcurve.Scalar) {
	for id := range xs {
		xs[id] = edcurve.ScalarZero()
		delete(xs, id)
	}
}

func clearEnvelopePayloads(envelopes []tss.Envelope) {
	for i := range envelopes {
		clear(envelopes[i].Payload)
		envelopes[i].Payload = nil
	}
}
