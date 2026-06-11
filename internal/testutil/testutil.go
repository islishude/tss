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
	"slices"

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

// MustPartySet returns a sorted party set {1, 2, ..., n}.
func MustPartySet(n int) []tss.PartyID {
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	return parties
}

// MustDeliverAll fans out envelopes to the session map using the provided
// handler. Outbound envelopes produced by each handle call are queued and
// processed in FIFO order until the queue drains. Fatal on error.
func MustDeliverAll[S any](
	tb interface{ Fatal(...any) },
	sessions map[tss.PartyID]S,
	envelopes []tss.Envelope,
	handler func(S, tss.Envelope) ([]tss.Envelope, error),
) {
	queue := make([]tss.Envelope, len(envelopes))
	copy(queue, envelopes)
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]

		session, ok := sessions[env.To]
		if !ok {
			tb.Fatal(fmt.Sprintf("no session for party %d", env.To))
		}
		out, err := handler(session, env)
		if err != nil {
			tb.Fatal(fmt.Sprintf("handle message from %d to %d: %v", env.From, env.To, err))
		}
		queue = append(queue, out...)
	}
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
func AssertProtocolError(tb interface{ Fatal(...any) }, err error, code string) *tss.ProtocolError {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
	if err == nil {
		tb.Fatal("expected ProtocolError, got nil")
		return nil
	}
	var pe *tss.ProtocolError
	if !errors.As(err, &pe) {
		tb.Fatal(fmt.Sprintf("expected *tss.ProtocolError, got %T: %v", err, err))
		return nil
	}
	if pe.Code != code {
		tb.Fatal(fmt.Sprintf("expected code %q, got %q: %v", code, pe.Code, pe))
	}
	return pe
}

// MustDecodeHex decodes a hex string into a byte slice. It calls t.Fatal if
// decoding fails, making it suitable for test fixture setup where a malformed
// hex literal is a programmer error.
func MustDecodeHex(tb interface{ Fatal(...any) }, s string) []byte {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(fmt.Sprintf("testutil.MustDecodeHex: invalid hex %q: %v", s, err))
		return nil
	}
	return b
}

// IsZeroBytes reports whether every byte in b is zero. A nil or empty slice
// returns true.
func IsZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// CloneByteSlices returns a deep copy of a [][]byte slice.
// Both the outer slice and each inner slice are independently copied.
// Nil inner slices are preserved as nil.
func CloneByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = slices.Clone(in[i])
	}
	return out
}

// AssertBigIntCleared fails if x is non-nil and has not been cleared (non-zero
// sign or non-empty backing words). A cleared big.Int has Sign() == 0 and
// zero-length Bits().
func AssertBigIntCleared(tb interface{ Fatal(...any) }, x *big.Int) {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
	if x == nil {
		return
	}
	if x.Sign() != 0 {
		tb.Fatal(fmt.Sprintf("big.Int not cleared: sign=%d", x.Sign()))
	}
	if len(x.Bits()) != 0 {
		tb.Fatal(fmt.Sprintf("big.Int not cleared: bits len=%d", len(x.Bits())))
	}
}

// AssertBytesCleared fails if b is non-nil and any byte is non-zero.
func AssertBytesCleared(tb interface{ Fatal(...any) }, b []byte) {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
	for i, v := range b {
		if v != 0 {
			tb.Fatal(fmt.Sprintf("byte at offset %d not cleared: 0x%02x", i, v))
		}
	}
}

// AssertMapCleared fails if m has any entries. This helper uses reflection-free
// iteration and is intended for maps that should be empty after Destroy/abort.
func AssertMapCleared[M ~map[K]V, K comparable, V any](tb interface{ Fatal(...any) }, m M) {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
	if len(m) != 0 {
		tb.Fatal(fmt.Sprintf("map not cleared: %d entries remain", len(m)))
	}
}

// DeliverEnvelope returns a copy of env with transport authentication set for
// guard validation. The authenticated party is set to env.From, simulating a
// delivery where the transport layer vouches for the sender identity.
func DeliverEnvelope(env tss.Envelope) tss.Envelope {
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = env.From
	return env
}

// CheckGolden compares raw bytes against a golden file. When the environment
// variable UPDATE_GOLDEN=1 is set, it writes the golden file (creating parent
// directories as needed). Otherwise it reads and asserts exact match.
func CheckGolden(tb interface{ Fatal(...any) }, golden string, raw []byte) {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
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
		tb.Fatal(fmt.Sprintf("reading golden %s: %v (run with UPDATE_GOLDEN=1 to generate)", golden, err))
		return
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		tb.Fatal(fmt.Sprintf("golden mismatch:\n  got:  %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex))))
	}
}
