package secp256k1

import (
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
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
	s.kShare.Destroy()
	s.gamma.Destroy()
	s.xBar.Destroy()
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
	clearPresignRound1ProofMap(s.round1Proofs)
	for id := range s.round1ProofEnvelopes {
		delete(s.round1ProofEnvelopes, id)
	}
	clearPresignRound2Map(s.round2)
	if s.startOpening != nil {
		s.startOpening.Destroy()
		s.startOpening = nil
	}
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
	for _, x := range xs {
		secret.ClearBigInt(x)
	}
	clear(xs)
}

func clearPresignRound1Map(xs map[tss.PartyID]presignRound1Payload) {
	for _, payload := range xs {
		clear(payload.Gamma)
		clear(payload.EncK)
		clear(payload.PaillierPublicKey)
	}
	clear(xs)
}

func clearPresignRound1ProofMap(xs map[tss.PartyID]presignRound1ProofPayload) {
	for _, payload := range xs {
		clear(payload.PublicRound1Hash)
		clear(payload.EncKProof)
	}
	clear(xs)
}

func clearPresignRound2Map(xs map[tss.PartyID]presignRound2Payload) {
	for _, payload := range xs {
		clear(payload.Delta.Ciphertext)
		clear(payload.Delta.Proof)
		clear(payload.Sigma.Ciphertext)
		clear(payload.Sigma.Proof)
		clear(payload.Round1Echo)
	}
	clear(xs)
}
