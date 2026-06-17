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
	if s.derivation != nil {
		s.derivation.Destroy()
		s.derivation = nil
	}
	clearScalarMap(s.partials)
	s.partialEnvelopes = nil
	clear(s.message)
	s.message = nil
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
	for _, pd := range s.partyData {
		if pd.share != nil {
			pd.share.Set(fed.NewScalar())
			pd.share = nil
		}
		clear(pd.chainCode)
		pd.chainCode = nil
		if pd.confirmation != nil {
			clear(pd.confirmation.ChainCode)
			pd.confirmation = nil
		}
	}
	clearScalars(s.ownPoly)
	clearEnvelopePayloads(s.ownMessages)
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
