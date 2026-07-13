package secp256k1

import (
	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

// Destroy clears local secret material retained by the keygen session.
// It delegates to abort for secret-bearing state, then releases non-secret storage.
// Destroy is safe to call on a nil receiver; it is idempotent because all
// sub-operations (clearScalarMap, PrivateKey.Destroy, KeyShare.Destroy) are
// themselves nil-safe.
func (s *KeygenSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	ctx := s.config.Ctx()
	store := s.lifecycleStore
	lease := s.lifecycleLease
	timeout := s.lifecycleTimeout
	finished := s.leaseFinished
	s.abort()
	s.mu.Unlock()
	if !finished {
		abortPresignLeaseBestEffort(ctx, store, lease, timeout)
	}
}

// Destroy clears local online signing state retained by the signing session.
// It delegates to abort for secret-bearing state (which includes clearing
// collected partial signatures via clearScalarMap), then releases non-secret
// storage including the public key and assembled signature bytes.
// Destroy is safe to call on a nil receiver; it is idempotent because all
// sub-operations are themselves nil-safe.
// The session owns the key generation decoded from LifecycleStore and destroys
// it on success, abort, or explicit cleanup.
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
	clear(s.attempt.PresignMetadata)
	clear(s.attempt.ExactOutbox)
	clear(s.attempt.OutboxDigest)
	clear(s.attempt.Delivery)
	clear(s.attempt.Completion)
	s.attempt = tssrun.SignAttemptRecord{}
}

func clearScalarMap(xs map[tss.PartyID]secp.Scalar) {
	for id := range xs {
		xs[id] = secp.ScalarZero()
		delete(xs, id)
	}
}
