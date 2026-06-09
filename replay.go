package tss

import (
	"crypto/sha256"
	"sync"
)

// InMemoryReplayCache is a simple mutex-protected ReplayCache for use in tests
// and single-process deployments. Production multi-process deployments should
// use a durable shared cache (e.g. Redis) keyed by session ID + slot key.
//
// MaxEntries limits the number of cached slots (0 = unlimited). When the
// limit is exceeded, an arbitrary entry is evicted to bound memory usage.
type InMemoryReplayCache struct {
	mu         sync.Mutex
	seen       map[messageSlotKey][32]byte
	maxEntries int
}

type messageSlotKey struct {
	protocol    ProtocolID
	sessionID   SessionID
	round       uint8
	from        PartyID
	to          PartyID
	payloadType PayloadType
}

// NewInMemoryReplayCache returns an initialized in-memory replay cache with a
// default bound of 100000 entries to prevent unbounded memory growth in
// long-running processes. For an explicit bound, use [NewBoundedReplayCache].
func NewInMemoryReplayCache() *InMemoryReplayCache {
	return NewBoundedReplayCache(100000)
}

// NewBoundedReplayCache returns an in-memory replay cache that evicts an
// arbitrary entry when the number of cached keys exceeds maxEntries.
// maxEntries must be positive.
func NewBoundedReplayCache(maxEntries int) *InMemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &InMemoryReplayCache{
		seen:       make(map[messageSlotKey][32]byte),
		maxEntries: maxEntries,
	}
}

// CheckAndStore implements [ReplayCache]. It atomically checks whether a message slot
// has been seen and returns nil on first use, [ErrDuplicateMessage] when the same
// transcript hash is replayed, or [ErrEquivocation] when a different transcript hash
// occupies the same slot.
//
// A nil receiver returns [ErrMissingReplayCache] (fail-closed) — callers must
// initialize the cache.
func (c *InMemoryReplayCache) CheckAndStore(slot MessageSlotKey, transcriptHash [32]byte) error {
	if c == nil {
		return ErrMissingReplayCache
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sk := messageSlotKey{
		protocol:    slot.Protocol,
		sessionID:   slot.SessionID,
		round:       slot.Round,
		from:        slot.From,
		to:          slot.To,
		payloadType: slot.PayloadType,
	}
	existing, ok := c.seen[sk]
	if !ok {
		if c.maxEntries > 0 && len(c.seen) >= c.maxEntries {
			for old := range c.seen {
				delete(c.seen, old)
				break
			}
		}
		c.seen[sk] = transcriptHash
		return nil
	}
	if existing == transcriptHash {
		return ErrDuplicateMessage
	}
	return ErrEquivocation
}

// SlotKeyFromEnvelope constructs a [MessageSlotKey] from the envelope's identifying fields,
// excluding the transcript hash so that different payloads for the same slot are detected
// as equivocation.
func SlotKeyFromEnvelope(env Envelope) MessageSlotKey {
	return MessageSlotKey{
		Protocol:    env.Protocol,
		SessionID:   env.SessionID,
		Round:       env.Round,
		From:        env.From,
		To:          env.To,
		PayloadType: env.PayloadType,
	}
}

// PayloadHashFromEnvelope returns the SHA-256 hash of the envelope payload.
// It is used with [ReplayCache.CheckAndStore] as the content discriminator:
// two messages in the same slot with different payload hashes are equivocation.
func PayloadHashFromEnvelope(env Envelope) [32]byte {
	return sha256.Sum256(env.Payload)
}
