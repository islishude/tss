package ed25519

import (
	"math/big"

	"github.com/islishude/tss"
)

// Destroy clears local secret material retained by the keygen session.
func (s *KeygenSession) Destroy() {
	if s == nil {
		return
	}
	clearBigIntMap(s.shares)
	clearBigInts(s.ownPoly)
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
	clearBigInt(s.d)
	clearBigInt(s.e)
	clearBigInt(s.deltaScalar)
	clearBigIntMap(s.partials)
	clear(s.message)
	s.d = nil
	s.e = nil
	s.deltaScalar = nil
	s.message = nil
}

func clearBigInts(xs []*big.Int) {
	for i := range xs {
		clearBigInt(xs[i])
		xs[i] = nil
	}
}

func clearBigIntMap(xs map[tss.PartyID]*big.Int) {
	for id, x := range xs {
		clearBigInt(x)
		delete(xs, id)
	}
}

func clearBigInt(x *big.Int) {
	if x == nil {
		return
	}
	clear(x.Bits())
	x.SetInt64(0)
}

func clearEnvelopePayloads(envelopes []tss.Envelope) {
	for i := range envelopes {
		clear(envelopes[i].Payload)
		envelopes[i].Payload = nil
	}
}
