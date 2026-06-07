// Package testutil provides shared test helpers used across TSS protocol tests.
// It contains deterministic randomness sources, wire-format mutation helpers,
// protocol-error assertions, fixture caches, and security-parameter overrides.
package testutil

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
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

// CloneEnvelope returns a deep copy of the given envelope.
func CloneEnvelope(in tss.Envelope) tss.Envelope {
	return tss.Envelope{
		Protocol:             in.Protocol,
		Version:              in.Version,
		SessionID:            in.SessionID,
		Round:                in.Round,
		From:                 in.From,
		To:                   in.To,
		PayloadType:          in.PayloadType,
		Payload:              append([]byte(nil), in.Payload...),
		TranscriptHash:       append([]byte(nil), in.TranscriptHash...),
		ConfidentialRequired: in.ConfidentialRequired,
	}
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
