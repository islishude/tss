package secp256k1

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
	for id, chainCode := range s.chainCodes {
		clear(chainCode)
		delete(s.chainCodes, id)
	}
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	if s.keyShare != nil {
		s.keyShare.Destroy()
	}
}

// Destroy clears local secret material retained by the presign session.
func (s *PresignSession) Destroy() {
	if s == nil {
		return
	}
	clearBigInt(s.kShare)
	clearBigInt(s.gamma)
	clearBigInt(s.xBar)
	s.kShare = nil
	s.gamma = nil
	s.xBar = nil
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	clearBigIntMap(s.deltas)
	clearBigIntMap(s.alphaDelta)
	clearBigIntMap(s.betaDelta)
	clearBigIntMap(s.alphaSigma)
	clearBigIntMap(s.betaSigma)
	clearPresignRound1Map(s.round1)
	clearPresignRound2Map(s.round2)
	if s.presign != nil {
		s.presign.Destroy()
	}
}

// Destroy clears local online signing partials retained by the signing session.
func (s *SignSession) Destroy() {
	if s == nil {
		return
	}
	clearBigIntMap(s.partials)
	clear(s.digest)
	s.digest = nil
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

func clearPresignRound1Map(xs map[tss.PartyID]presignRound1Payload) {
	for id, payload := range xs {
		clear(payload.Gamma)
		clear(payload.EncK)
		clear(payload.EncKProof)
		clear(payload.PaillierPublicKey)
		delete(xs, id)
	}
}

func clearPresignRound2Map(xs map[tss.PartyID]presignRound2Payload) {
	for id, payload := range xs {
		clear(payload.Delta.Ciphertext)
		clear(payload.Delta.Proof)
		clear(payload.Sigma.Ciphertext)
		clear(payload.Sigma.Proof)
		clear(payload.Round1Echo)
		delete(xs, id)
	}
}
