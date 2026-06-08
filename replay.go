package tss

import "sync"

// InMemoryReplayCache is a simple sync.Map-backed ReplayCache for use in tests
// and single-process deployments. Production multi-process deployments should
// use a durable shared cache (e.g. Redis) keyed by session ID + replay key.
//
// MaxEntries limits the number of cached replay keys (0 = unlimited). When the
// limit is exceeded, an arbitrary entry is evicted to bound memory usage.
type InMemoryReplayCache struct {
	mu         sync.Mutex
	seen       map[replayCacheKey]struct{}
	maxEntries int
}

type replayCacheKey struct {
	protocol       ProtocolID
	sessionID      SessionID
	round          uint8
	from           PartyID
	to             PartyID
	payloadType    PayloadType
	transcriptHash [32]byte
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
		seen:       make(map[replayCacheKey]struct{}),
		maxEntries: maxEntries,
	}
}

// MarkIfNew returns true and marks the key as seen on first encounter.
// Subsequent calls with the same key return false.
// A nil receiver returns false (fail-closed) — callers must initialize the cache.
//
// When maxEntries is non-zero and the map has reached the limit, an arbitrary
// entry is evicted before inserting the new key to bound memory usage.
func (c *InMemoryReplayCache) MarkIfNew(key ReplayKey) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rk := replayCacheKey{
		protocol:       key.Protocol,
		sessionID:      key.SessionID,
		round:          key.Round,
		from:           key.From,
		to:             key.To,
		payloadType:    key.PayloadType,
		transcriptHash: key.TranscriptHash,
	}
	if _, ok := c.seen[rk]; ok {
		return false
	}
	if c.maxEntries > 0 && len(c.seen) >= c.maxEntries {
		for old := range c.seen {
			delete(c.seen, old)
			break
		}
	}
	c.seen[rk] = struct{}{}
	return true
}
