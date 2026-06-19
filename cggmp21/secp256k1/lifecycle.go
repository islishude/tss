package secp256k1

import (
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
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
	clear(s.attempt.CanonicalBaseEnvelopeBytes)
	clear(s.attempt.Digest)
	s.attempt = SignAttemptRecord{}
}

func clearBigIntMap(xs map[tss.PartyID]*big.Int) {
	for _, x := range xs {
		secret.ClearBigInt(x)
	}
	clear(xs)
}

func clearEncProof(p *zkpai.EncProof) {
	if p == nil {
		return
	}
	secret.ClearBigInt(p.S)
	secret.ClearBigInt(p.A)
	secret.ClearBigInt(p.C)
	secret.ClearBigInt(p.Z1)
	secret.ClearBigInt(p.Z2)
	secret.ClearBigInt(p.Z3)
	clear(p.TranscriptHash)
	*p = zkpai.EncProof{}
}

func clearAffGProof(p *zkpai.AffGProof) {
	if p == nil {
		return
	}
	secret.ClearBigInt(p.A)
	secret.ClearBigInt(p.By)
	secret.ClearBigInt(p.E)
	secret.ClearBigInt(p.S)
	secret.ClearBigInt(p.F)
	secret.ClearBigInt(p.T)
	secret.ClearBigInt(p.Y)
	secret.ClearBigInt(p.Z1)
	secret.ClearBigInt(p.Z2)
	secret.ClearBigInt(p.Z3)
	secret.ClearBigInt(p.Z4)
	secret.ClearBigInt(p.W)
	secret.ClearBigInt(p.WY)
	clear(p.TranscriptHash)
	*p = zkpai.AffGProof{}
}
