package tss

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestNewReplayCacheConfiguresCapacity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		new  func() *InMemoryReplayCache
		want int
	}{
		{
			name: "bounded default",
			new:  func() *InMemoryReplayCache { return NewBoundedReplayCache(0) },
			want: defaultReplayCacheMaxEntries,
		},
		{
			name: "bounded custom",
			new:  func() *InMemoryReplayCache { return NewBoundedReplayCache(10) },
			want: 10,
		},
		{
			name: "in-memory default",
			new:  NewInMemoryReplayCache,
			want: defaultReplayCacheMaxEntries,
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := tc.new()
			if c == nil {
				t.Fatal("expected non-nil cache")
			}
			if c.maxEntries != tc.want {
				t.Fatalf("maxEntries = %d, want %d", c.maxEntries, tc.want)
			}
		})
	}
}

func TestReplayCacheCheckAndStore(t *testing.T) {
	t.Parallel()

	slot := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, PayloadType: "msg"}
	hash1 := sha256.Sum256([]byte("payload1"))
	hash2 := sha256.Sum256([]byte("payload2"))

	tests := []struct {
		name    string
		setup   func(*InMemoryReplayCache)
		hash    [32]byte
		wantErr error
	}{
		{
			name: "first use accepts",
			hash: hash1,
		},
		{
			name: "duplicate rejects",
			setup: func(c *InMemoryReplayCache) {
				_ = c.CheckAndStore(slot, hash1)
			},
			hash:    hash1,
			wantErr: ErrDuplicateMessage,
		},
		{
			name: "equivocation rejects",
			setup: func(c *InMemoryReplayCache) {
				_ = c.CheckAndStore(slot, hash1)
			},
			hash:    hash2,
			wantErr: ErrEquivocation,
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := NewBoundedReplayCache(100)
			if tc.setup != nil {
				tc.setup(c)
			}
			err := c.CheckAndStore(slot, tc.hash)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckAndStore: %v", err)
			}
		})
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

func TestReplayCacheSlotDimensionsIndependent(t *testing.T) {
	t.Parallel()

	base := MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, To: 2, PayloadType: "msg"}
	hash := sha256.Sum256([]byte("payload"))

	tests := []struct {
		name string
		next MessageSlotKey
	}{
		{
			name: "different sessions",
			next: MessageSlotKey{Protocol: "test", SessionID: SessionID{0x02}, Round: 1, From: 1, To: 2, PayloadType: "msg"},
		},
		{
			name: "different rounds",
			next: MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 2, From: 1, To: 2, PayloadType: "msg"},
		},
		{
			name: "p2p and broadcast",
			next: MessageSlotKey{Protocol: "test", SessionID: SessionID{0x01}, Round: 1, From: 1, To: 0, PayloadType: "msg"},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := NewBoundedReplayCache(100)
			if err := c.CheckAndStore(base, hash); err != nil {
				t.Fatalf("store base slot: %v", err)
			}
			if err := c.CheckAndStore(tc.next, hash); err != nil {
				t.Fatalf("independent slot rejected: %v", err)
			}
		})
	}
}
