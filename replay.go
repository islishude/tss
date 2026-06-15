package tss

import (
	"crypto/sha256"
	"sync"
)

// InMemoryReplayCache is a simple mutex-protected ReplayCache for use in tests
// and single-process deployments. Production multi-process deployments should
// use a durable shared cache (e.g. Redis) keyed by session ID + slot key.
//
// MaxEntries limits the number of cached slots (0 = use default of 100000).
// Eviction is FIFO: when the limit is exceeded, the oldest entry is removed
// to bound memory usage while preserving recent entries for replay detection.
type InMemoryReplayCache struct {
	mu         sync.Mutex
	seen       map[messageSlotKey][32]byte
	order      []messageSlotKey // FIFO insertion order for deterministic eviction
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

const defaultReplayCacheMaxEntries = 100000

// NewInMemoryReplayCache returns an initialized in-memory replay cache with a
// default bound of 100000 entries to prevent unbounded memory growth in
// long-running processes. For an explicit bound, use [NewBoundedReplayCache].
func NewInMemoryReplayCache() *InMemoryReplayCache {
	return NewBoundedReplayCache(defaultReplayCacheMaxEntries)
}

// NewBoundedReplayCache returns an in-memory replay cache with a FIFO eviction
// policy: when the number of cached keys exceeds maxEntries, the oldest entry
// (by insertion order) is evicted.
//
// maxEntries must be positive. Values <= 0 are replaced with the default of
// [defaultReplayCacheMaxEntries]. The default is intentionally large enough to
// accommodate normal protocol message volumes; callers operating in constrained
// environments should pick an explicit value based on expected throughput.
func NewBoundedReplayCache(maxEntries int) *InMemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = defaultReplayCacheMaxEntries
	}
	return &InMemoryReplayCache{
		seen:       make(map[messageSlotKey][32]byte, maxEntries),
		order:      make([]messageSlotKey, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

// CheckAndStore implements [ReplayCache]. It atomically checks whether a message slot
// has been seen and returns nil on first use, [ErrDuplicateMessage] when the same
// payload hash is replayed, or [ErrEquivocation] when a different payload hash
// occupies the same slot.
//
// A nil receiver returns [ErrMissingReplayCache] (fail-closed) — callers must
// initialize the cache.
func (c *InMemoryReplayCache) CheckAndStore(slot MessageSlotKey, payloadHash [32]byte) error {
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
		// FIFO eviction: remove the oldest entry before inserting a new one
		// when at capacity. This guarantees deterministic eviction order and
		// prevents an attacker from selectively evicting arbitrary entries
		// through map iteration randomization.
		if len(c.order) >= c.maxEntries {
			oldest := c.order[0]
			delete(c.seen, oldest)
			c.order = c.order[1:]
		}
		c.seen[sk] = payloadHash
		c.order = append(c.order, sk)
		return nil
	}
	if existing == payloadHash {
		return ErrDuplicateMessage
	}
	return ErrEquivocation
}

// SlotKeyFromEnvelope constructs a [MessageSlotKey] from the envelope's identifying fields.
// The payload is excluded so that different payloads for the same slot are detected as
// equivocation.
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
