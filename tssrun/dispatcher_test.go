package tssrun

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

func TestDispatcherRoutesSessionAndSendsOutbox(t *testing.T) {
	ctx := context.Background()
	in := testInboundEnvelope(t)
	registry := NewMemorySessionRegistry()
	out := testEnvelope(t, in.SessionID(), 1, 2)
	session := &testSession{out: []tss.Envelope{out}}
	key := SessionKey{Protocol: in.Protocol(), SessionID: in.SessionID(), Party: 2}
	if err := registry.Put(ctx, key, session); err != nil {
		t.Fatalf("Put: %v", err)
	}
	transport := &captureTransport{}
	dispatcher := Dispatcher{Self: 2, Registry: registry, Transport: transport}
	if err := dispatcher.Dispatch(ctx, in); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if session.handled != 1 {
		t.Fatalf("session handled %d envelopes, want 1", session.handled)
	}
	if len(transport.sent) != 1 || transport.sent[0].From != out.From {
		t.Fatalf("transport sent %#v, want one outbox envelope", transport.sent)
	}
}

func TestDispatcherRejectsUnknownByDefault(t *testing.T) {
	dispatcher := Dispatcher{Self: 2, Registry: NewMemorySessionRegistry()}
	err := dispatcher.Dispatch(context.Background(), testInboundEnvelope(t))
	if !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("expected ErrUnknownSession, got %v", err)
	}
}

func TestDurableBufferUnknownSessionStoresWithoutDelivery(t *testing.T) {
	ctx := context.Background()
	in := testInboundEnvelope(t)
	store := NewMemoryUnknownEnvelopeStore()
	dispatcher := Dispatcher{
		Self:     2,
		Registry: NewMemorySessionRegistry(),
		Unknown:  DurableBufferUnknownSession{Store: store},
	}
	if err := dispatcher.Dispatch(ctx, in); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	buffered, err := store.LoadBySession(ctx, in.Protocol(), in.SessionID())
	if err != nil {
		t.Fatalf("LoadBySession: %v", err)
	}
	if len(buffered) != 1 || buffered[0].From() != in.From() {
		t.Fatalf("buffered %#v, want original envelope", buffered)
	}
}

type testSession struct {
	out       []tss.Envelope
	err       error
	handled   int
	completed bool
	destroyed bool
}

func (s *testSession) Handle(tss.InboundEnvelope) ([]tss.Envelope, error) {
	s.handled++
	return append([]tss.Envelope(nil), s.out...), s.err
}

func (s *testSession) Completed() bool { return s.completed }

func (s *testSession) Destroy() { s.destroyed = true }

type captureTransport struct {
	sent []tss.Envelope
}

func (t *captureTransport) SendAll(_ context.Context, envelopes []tss.Envelope) error {
	t.sent = append(t.sent, envelopes...)
	return nil
}

func testInboundEnvelope(t *testing.T) tss.InboundEnvelope {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	env := testEnvelope(t, sessionID, 1, 2)
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	in, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{Peer: 1, Protection: tss.ChannelConfidential})
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	return in
}

func testEnvelope(t *testing.T, sessionID tss.SessionID, from, to tss.PartyID) tss.Envelope {
	t.Helper()
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       1,
		From:        from,
		To:          to,
		PayloadType: "test.payload",
		Payload:     []byte("payload"),
	})
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	return env
}
