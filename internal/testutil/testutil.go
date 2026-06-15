// Package testutil provides shared test helpers used across TSS protocol tests.
// It contains deterministic randomness sources, wire-format mutation helpers,
// protocol-error assertions, fixture caches, secret-cleanup assertions, and
// security-parameter overrides.
package testutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/islishude/tss"
)

// deterministicReader adapts *rand.Rand to io.Reader.
type deterministicReader struct {
	rng *rand.Rand
}

// Read fills p from the deterministic pseudo-random source.
func (r *deterministicReader) Read(p []byte) (int, error) {
	// Fill with random bytes from the deterministic source.
	for i := range p {
		p[i] = byte(r.rng.Uint32N(256))
	}
	return len(p), nil
}

// DeterministicReader returns an io.Reader that produces a deterministic stream
// of pseudo-random bytes seeded by the given value. Use only in tests.
//
//nolint:gosec // math/rand is intentional for deterministic test fixtures
func DeterministicReader(seed int64) io.Reader {
	return &deterministicReader{rng: rand.New(rand.NewPCG(uint64(seed), uint64(seed)))}
}

// SeedFromEnv checks the TSS_TEST_SEED environment variable. When set, it parses
// the value (hex with optional 0x prefix, or decimal) and returns the seed.
// When unset, it returns defaultSeed. The seed is always logged via t.Logf so
// CI failures are reproducible: set TSS_TEST_SEED to the logged value and re-run.
func SeedFromEnv(t testing.TB, defaultSeed int64) int64 {
	t.Helper()
	val := os.Getenv("TSS_TEST_SEED")
	if val == "" {
		t.Logf("seed=%016x (set TSS_TEST_SEED to reproduce)", defaultSeed)
		return defaultSeed
	}
	seed, err := parseSeed(val)
	if err != nil {
		t.Fatalf("TSS_TEST_SEED=%q: %v", val, err)
	}
	t.Logf("seed=%016x (from TSS_TEST_SEED)", seed)
	return seed
}

// DeterministicReaderFromEnv returns a deterministic io.Reader seeded from
// TSS_TEST_SEED when set, or the provided defaultSeed otherwise.
func DeterministicReaderFromEnv(t testing.TB, defaultSeed int64) io.Reader {
	t.Helper()
	return DeterministicReader(SeedFromEnv(t, defaultSeed))
}

// parseSeed parses a seed string as hex (with optional 0x prefix) or decimal.
func parseSeed(s string) (int64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) > 0 {
		// Try hex first.
		b, err := hex.DecodeString(s)
		if err == nil && len(b) > 0 && len(b) <= 8 {
			var v int64
			for i := range b {
				v = v*256 + int64(b[i])
			}
			return v, nil
		}
	}
	// Fall back to decimal.
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid seed: must be hex (with optional 0x prefix) or decimal int64")
	}
	return v, nil
}

// MustSessionID creates a deterministic 32-byte session identifier from a seed.
// Different seeds produce different identifiers, enabling stable test scenarios.
func MustSessionID(seed int64) tss.SessionID {
	rng := DeterministicReader(seed)
	var id tss.SessionID
	if _, err := io.ReadFull(rng, id[:]); err != nil {
		panic("deterministic reader should never fail: " + err.Error())
	}
	return id
}

// OtherParty returns any party in the set that is not self.
// It panics when no other party exists, making it suitable for test fixture
// setup where a single-party set is a programmer error.
func OtherParty(parties tss.PartySet, self tss.PartyID) tss.PartyID {
	for _, id := range parties {
		if id != self {
			return id
		}
	}
	panic("testutil.OtherParty: no other party in set")
}

// MustPartySet returns a sorted party set {1, 2, ..., n}.
func MustPartySet(n int) []tss.PartyID {
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	return parties
}

// MutateBytes returns a copy of in with bit 0 of the first byte flipped.
// If the input is empty, the output is empty.
func MutateBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	if len(out) > 0 {
		out[0] ^= 1
	}
	return out
}

// AssertProtocolError asserts that err is a *tss.ProtocolError with the given
// code. Returns the typed error for further inspection.
func AssertProtocolError(tb testing.TB, err error, code string) *tss.ProtocolError {
	tb.Helper()
	if err == nil {
		tb.Fatal("expected ProtocolError, got nil")
		return nil
	}
	var pe *tss.ProtocolError
	if !errors.As(err, &pe) {
		tb.Fatalf("expected *tss.ProtocolError, got %T: %v", err, err)
		return nil
	}
	if pe.Code != code {
		tb.Fatalf("expected code %q, got %q: %v", code, pe.Code, pe)
	}
	return pe
}

// MustDecodeHex decodes a hex string into a byte slice. It calls t.Fatal if
// decoding fails, making it suitable for test fixture setup where a malformed
// hex literal is a programmer error.
func MustDecodeHex(tb testing.TB, s string) []byte {
	tb.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("testutil.MustDecodeHex: invalid hex %q: %v", s, err)
		return nil
	}
	return b
}

// IsZeroBytes reports whether every byte in b is zero. A nil or empty slice
// returns true. use [wire.IsAllZero] for constant-time usage.
func IsZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// AssertBigIntCleared fails if x is non-nil and has not been cleared (non-zero
// sign or non-empty backing words). A cleared big.Int has Sign() == 0 and
// zero-length Bits().
func AssertBigIntCleared(tb testing.TB, x *big.Int) {
	tb.Helper()

	if x == nil {
		return
	}
	if x.Sign() != 0 {
		tb.Fatalf("big.Int not cleared: sign=%d", x.Sign())
	}
	if len(x.Bits()) != 0 {
		tb.Fatalf("big.Int not cleared: bits len=%d", len(x.Bits()))
	}
}

// AssertBytesCleared fails if b is non-nil and any byte is non-zero.
func AssertBytesCleared(tb testing.TB, b []byte) {
	tb.Helper()

	for i, v := range b {
		if v != 0 {
			tb.Fatalf("byte at offset %d not cleared: 0x%02x", i, v)
		}
	}
}

// AssertMapCleared fails if m has any entries. This helper uses reflection-free
// iteration and is intended for maps that should be empty after Destroy/abort.
func AssertMapCleared[M ~map[K]V, K comparable, V any](tb testing.TB, m M) {
	tb.Helper()

	if len(m) != 0 {
		tb.Fatalf("map not cleared: %d entries remain", len(m))
	}
}

// DeliverEnvelope opens env as an authenticated inbound envelope for guard validation.
// It defaults to confidential delivery so secret-bearing test messages satisfy
// protocol policies unless a test explicitly overrides the receive facts.
func DeliverEnvelope(env tss.Envelope) tss.InboundEnvelope {
	in, err := OpenInboundEnvelope(env, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: tss.ChannelConfidential,
		ChannelID:  "test",
		PeerKeyID:  fmt.Sprintf("party-%d", env.From),
		ReceivedAt: time.Unix(1, 0),
	}, nil)
	if err != nil {
		panic(fmt.Sprintf("deliver envelope: %v", err))
	}
	return in
}

// DeliverEnvelopeWithProtection opens env with the requested channel protection.
func DeliverEnvelopeWithProtection(env tss.Envelope, protection tss.ChannelProtection) tss.InboundEnvelope {
	in, err := OpenInboundEnvelope(env, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: protection,
		ChannelID:  "test",
		PeerKeyID:  fmt.Sprintf("party-%d", env.From),
		ReceivedAt: time.Unix(1, 0),
	}, nil)
	if err != nil {
		panic(fmt.Sprintf("deliver envelope: %v", err))
	}
	return in
}

// OpenInboundEnvelope opens env with explicit receive facts and an optional
// broadcast certificate.
func OpenInboundEnvelope(env tss.Envelope, info tss.ReceiveInfo, cert *tss.BroadcastCertificate) (tss.InboundEnvelope, error) {
	raw, err := env.MarshalBinary()
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	return tss.OpenEnvelope(raw, info, tss.WithBroadcastCertificate(cert))
}

// CheckGolden compares raw bytes against a golden file. When the environment
// variable UPDATE_GOLDEN=1 is set, it writes the golden file (creating parent
// directories as needed). Otherwise it reads and asserts exact match.
func CheckGolden(tb testing.TB, golden string, raw []byte) {
	tb.Helper()

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o700); err != nil {
			tb.Fatal(err)
			return
		}
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
			tb.Fatal(err)
		}
		return
	}
	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		tb.Fatalf("reading golden %s: %v (run with UPDATE_GOLDEN=1 to generate)", golden, err)
		return
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		tb.Fatalf("golden mismatch:\n  got:  %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}
}
