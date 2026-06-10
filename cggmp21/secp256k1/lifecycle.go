package secp256k1

import (
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

// Destroy clears local secret material retained by the keygen session.
// It delegates to abort for secret-bearing state, then releases non-secret storage.
// Destroy is safe to call on a nil receiver; it is idempotent because all
// sub-operations (clearBigIntMap, PrivateKey.Destroy, KeyShare.Destroy) are
// themselves nil-safe.
func (s *KeygenSession) Destroy() {
	if s == nil {
		return
	}
	s.abort()
	for id := range s.commits {
		delete(s.commits, id)
	}
	for id := range s.confirmations {
		delete(s.confirmations, id)
	}
	if s.keyShare != nil {
		s.keyShare.Destroy()
		s.keyShare = nil
	}
}

// Destroy clears local secret material retained by the presign session.
// It delegates to abort for secret-bearing state, then releases non-secret storage.
// Destroy is safe to call on a nil receiver; it is idempotent because all
// sub-operations are themselves nil-safe.
func (s *PresignSession) Destroy() {
	if s == nil {
		return
	}
	s.abort()
	clearPresignRound1ProofMap(s.round1Proofs)
	for id := range s.round1ProofEnvelopes {
		delete(s.round1ProofEnvelopes, id)
	}
}

// Destroy clears local online signing state retained by the signing session.
// It delegates to abort for secret-bearing state (which includes clearing
// collected partial signatures via clearBigIntMap), then releases non-secret
// storage including the public key and assembled signature bytes.
// Destroy is safe to call on a nil receiver; it is idempotent because all
// sub-operations are themselves nil-safe.
// The session's key and presign references are caller-owned and are NOT
// destroyed — callers must destroy those separately.
func (s *SignSession) Destroy() {
	if s == nil {
		return
	}
	s.abort()
	clear(s.publicKey)
	s.publicKey = nil
	if s.signature != nil {
		clear(s.signature.R)
		clear(s.signature.S)
	}
	s.signature = nil
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
