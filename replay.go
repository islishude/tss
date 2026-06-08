package tss

import "sync"

// InMemoryReplayCache is a simple sync.Map-backed ReplayCache for use in tests
// and single-process deployments. Production multi-process deployments should
// use a durable shared cache (e.g. Redis) keyed by session ID + replay key.
type InMemoryReplayCache struct {
	mu   sync.Mutex
	seen map[replayCacheKey]struct{}
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

// NewInMemoryReplayCache returns an initialized in-memory replay cache.
func NewInMemoryReplayCache() *InMemoryReplayCache {
	return &InMemoryReplayCache{
		seen: make(map[replayCacheKey]struct{}),
	}
}

// MarkIfNew returns true and marks the key as seen on first encounter.
// Subsequent calls with the same key return false.
// A nil receiver returns false (fail-closed) — callers must initialize the cache.
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
	c.seen[rk] = struct{}{}
	return true
}
