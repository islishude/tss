package tss

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestNewBoundedReplayCacheDefaultSize(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(0)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.maxEntries != defaultReplayCacheMaxEntries {
		t.Fatalf("maxEntries = %d, want %d", c.maxEntries, defaultReplayCacheMaxEntries)
	}
}

func TestNewBoundedReplayCacheCustomSize(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(10)
	if c.maxEntries != 10 {
		t.Fatalf("maxEntries = %d, want 10", c.maxEntries)
	}
}

func TestNewInMemoryReplayCacheDefaultSize(t *testing.T) {
	t.Parallel()
	c := NewInMemoryReplayCache()
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.maxEntries != defaultReplayCacheMaxEntries {
		t.Fatalf("maxEntries = %d, want %d", c.maxEntries, defaultReplayCacheMaxEntries)
	}
}

func TestReplayCacheNilCheckAndStore(t *testing.T) {
	t.Parallel()
	var c *InMemoryReplayCache
	err := c.CheckAndStore(MessageSlotKey{}, [32]byte{})
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("expected ErrMissingReplayCache, got %v", err)
	}
}

func TestReplayCacheFirstUse(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(100)
	slot := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, PayloadType: "msg"}
	hash := sha256.Sum256([]byte("payload1"))
	if err := c.CheckAndStore(slot, hash); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
}

func TestReplayCacheDuplicateRejected(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(100)
	slot := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, PayloadType: "msg"}
	hash := sha256.Sum256([]byte("payload1"))
	_ = c.CheckAndStore(slot, hash)
	if err := c.CheckAndStore(slot, hash); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("expected ErrDuplicateMessage, got %v", err)
	}
}

func TestReplayCacheEquivocationRejected(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(100)
	slot := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, PayloadType: "msg"}
	hash1 := sha256.Sum256([]byte("payload1"))
	hash2 := sha256.Sum256([]byte("payload2"))
	_ = c.CheckAndStore(slot, hash1)
	if err := c.CheckAndStore(slot, hash2); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected ErrEquivocation, got %v", err)
	}
}

func TestReplayCacheFIFOEviction(t *testing.T) {
	t.Parallel()
	capacity := 3
	c := NewBoundedReplayCache(capacity)

	// Fill the cache.
	for i := range capacity {
		slot := MessageSlotKey{Protocol: "test", SessionID: SessionID{byte(i)}, From: PartyID(i + 1), PayloadType: "msg"}
		hash := sha256.Sum256([]byte{byte(i)})
		if err := c.CheckAndStore(slot, hash); err != nil {
			t.Fatalf("fill slot %d: %v", i, err)
		}
	}
	if len(c.order) != capacity {
		t.Fatalf("order length = %d, want %d", len(c.order), capacity)
	}

	// Insert one more — the oldest (i=0) should be evicted.
	slot := MessageSlotKey{Protocol: "test", SessionID: SessionID{0xff}, From: 99, PayloadType: "msg"}
	hash := sha256.Sum256([]byte{0xff})
	if err := c.CheckAndStore(slot, hash); err != nil {
		t.Fatalf("insert after fill: %v", err)
	}
	if len(c.order) != capacity {
		t.Fatalf("order length after eviction = %d, want %d", len(c.order), capacity)
	}

	// The evicted entry must be re-accepted as new.
	evicted := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x00}, From: 1, PayloadType: "msg"}
	evictedHash := sha256.Sum256([]byte{0x00})
	if err := c.CheckAndStore(evicted, evictedHash); err != nil {
		t.Fatalf("evicted entry should be re-acceptable: %v", err)
	}
}

func TestSlotKeyFromEnvelope(t *testing.T) {
	t.Parallel()
	env := Envelope{
		Protocol:    "frost-ed25519",
		SessionID:   SessionID{0xaa, 0xbb},
		Round:       2,
		From:        5,
		To:          3,
		PayloadType: "sign.partial",
		Payload:     []byte("unused"),
	}
	slot := SlotKeyFromEnvelope(env)
	if slot.Protocol != "frost-ed25519" {
		t.Fatalf("Protocol = %q", slot.Protocol)
	}
	if slot.SessionID != env.SessionID {
		t.Fatalf("SessionID mismatch")
	}
	if slot.Round != 2 {
		t.Fatalf("Round = %d", slot.Round)
	}
	if slot.From != 5 {
		t.Fatalf("From = %d", slot.From)
	}
	if slot.To != 3 {
		t.Fatalf("To = %d", slot.To)
	}
	if slot.PayloadType != "sign.partial" {
		t.Fatalf("PayloadType = %q", slot.PayloadType)
	}
}

func TestPayloadHashFromEnvelopeDeterministic(t *testing.T) {
	t.Parallel()
	env := Envelope{Payload: []byte("hello")}
	h1 := PayloadHashFromEnvelope(env)
	h2 := PayloadHashFromEnvelope(env)
	if h1 != h2 {
		t.Fatal("PayloadHashFromEnvelope is not deterministic")
	}
	// Different payload → different hash.
	env2 := Envelope{Payload: []byte("world")}
	h3 := PayloadHashFromEnvelope(env2)
	if h1 == h3 {
		t.Fatal("different payloads produced same hash")
	}
}

func TestReplayCacheDifferentSessionsIndependent(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(100)
	slot1 := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, PayloadType: "msg"}
	slot2 := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x02}, Round: 1, From: 1, PayloadType: "msg"}
	hash := sha256.Sum256([]byte("payload"))

	_ = c.CheckAndStore(slot1, hash)
	if err := c.CheckAndStore(slot2, hash); err != nil {
		t.Fatalf("different session should be independent: %v", err)
	}
}

func TestReplayCacheDifferentRoundsIndependent(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(100)
	slot1 := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, PayloadType: "msg"}
	slot2 := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 2, From: 1, PayloadType: "msg"}
	hash := sha256.Sum256([]byte("payload"))

	_ = c.CheckAndStore(slot1, hash)
	if err := c.CheckAndStore(slot2, hash); err != nil {
		t.Fatalf("different round should be independent: %v", err)
	}
}

func TestReplayCacheP2PvsBroadcastIndependent(t *testing.T) {
	t.Parallel()
	c := NewBoundedReplayCache(100)
	// p2p has To != 0, broadcast has To == 0.
	slotP2P := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, To: 2, PayloadType: "msg"}
	slotBC := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, To: 0, PayloadType: "msg"}
	hash := sha256.Sum256([]byte("payload"))

	_ = c.CheckAndStore(slotP2P, hash)
	if err := c.CheckAndStore(slotBC, hash); err != nil {
		t.Fatalf("p2p and broadcast should be independent: %v", err)
	}
}
