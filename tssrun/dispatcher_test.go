package tssrun

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/islishude/tss"
)

func TestDispatcherReturnsCallerOwnedOutbox(t *testing.T) {
	ctx := context.Background()
	in := testInboundEnvelope(t)
	registry := NewMemorySessionRegistry()
	out := testEnvelope(t, in.SessionID(), 1, 2)
	session := &testSession{out: []tss.Envelope{out}, descriptor: testDispatchDescriptor(in, 2)}
	key := SessionKey{Protocol: in.Protocol(), SessionID: in.SessionID(), Party: 2}
	if err := registry.Put(ctx, key, session); err != nil {
		t.Fatalf("Put: %v", err)
	}
	dispatcher := Dispatcher{Self: 2, Registry: registry}
	result, err := dispatcher.Dispatch(ctx, in)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	defer result.Destroy()
	if session.handled != 1 {
		t.Fatalf("session handled %d envelopes, want 1", session.handled)
	}
	if len(result.Outbox) != 1 || result.Outbox[0].From != out.From || result.InputDigest != in.Digest() {
		t.Fatalf("dispatch result %#v, want one exact outbox envelope", result)
	}
	clone := result.Clone()
	defer clone.Destroy()
	result.Outbox[0].Payload[0] ^= 0xff
	if slices.Equal(result.Outbox[0].Payload, clone.Outbox[0].Payload) {
		t.Fatal("DispatchResult.Clone exposed an outbox alias")
	}
}

func TestDispatcherRejectsUnknownByDefault(t *testing.T) {
	dispatcher := Dispatcher{Self: 2, Registry: NewMemorySessionRegistry()}
	_, err := dispatcher.Dispatch(context.Background(), testInboundEnvelope(t))
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
	if _, err := dispatcher.Dispatch(ctx, in); err != nil {
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

func TestMemoryUnknownEnvelopeStoreRejectsWhenBounded(t *testing.T) {
	ctx := context.Background()
	in := testInboundEnvelope(t)
	sameSession := testEnvelope(t, in.SessionID(), 1, 2)
	raw, err := sameSession.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	second, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{Peer: 1, Protection: tss.ChannelConfidential})
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}

	perSession := NewBoundedMemoryUnknownEnvelopeStore(2, 1)
	if err := perSession.PutUnknown(ctx, in); err != nil {
		t.Fatalf("PutUnknown first: %v", err)
	}
	if err := perSession.PutUnknown(ctx, second); !errors.Is(err, ErrUnknownSessionBufferFull) {
		t.Fatalf("PutUnknown over per-session quota error = %v, want ErrUnknownSessionBufferFull", err)
	}

	global := NewBoundedMemoryUnknownEnvelopeStore(1, 1)
	other := testInboundEnvelope(t)
	if err := global.PutUnknown(ctx, in); err != nil {
		t.Fatalf("PutUnknown global first: %v", err)
	}
	if err := global.PutUnknown(ctx, other); !errors.Is(err, ErrUnknownSessionBufferFull) {
		t.Fatalf("PutUnknown over global quota error = %v, want ErrUnknownSessionBufferFull", err)
	}
	if err := global.DeleteBySession(ctx, in.Protocol(), in.SessionID()); err != nil {
		t.Fatalf("DeleteBySession: %v", err)
	}
	if err := global.PutUnknown(ctx, other); err != nil {
		t.Fatalf("PutUnknown after delete: %v", err)
	}
}

func TestDispatchInboundOpensRawEnvelopeBeforeRouting(t *testing.T) {
	ctx := context.Background()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	env := testEnvelope(t, sessionID, 1, 2)
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	registry := NewMemorySessionRegistry()
	session := &testSession{descriptor: SessionDescriptor{
		Protocol: env.Protocol, Kind: RunKeygen, SessionID: env.SessionID, Party: 2, PlanDigest: make([]byte, 32),
	}}
	key := SessionKey{Protocol: env.Protocol, SessionID: env.SessionID, Party: 2}
	if err := registry.Put(ctx, key, session); err != nil {
		t.Fatalf("Put: %v", err)
	}
	dispatcher := Dispatcher{Self: 2, Registry: registry}
	_, err = DispatchInbound(ctx, EnvelopeReceiver{}, &dispatcher, raw, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: tss.ChannelConfidential,
	})
	if err != nil {
		t.Fatalf("DispatchInbound: %v", err)
	}
	if session.handled != 1 {
		t.Fatalf("session handled %d envelopes, want 1", session.handled)
	}
}

type testSession struct {
	out        []tss.Envelope
	err        error
	handled    int
	completed  bool
	destroyed  bool
	descriptor SessionDescriptor
}

func (s *testSession) Handle(context.Context, tss.InboundEnvelope) ([]tss.Envelope, error) {
	s.handled++
	return slices.Clone(s.out), s.err
}

func (s *testSession) Descriptor() SessionDescriptor { return s.descriptor.Clone() }

func (s *testSession) Status() SessionState {
	if s.completed {
		return SessionSucceeded
	}
	return SessionActive
}

func (s *testSession) Abort(context.Context, string) error { return nil }

func (s *testSession) Close(context.Context) error { s.destroyed = true; return nil }

func testDispatchDescriptor(in tss.InboundEnvelope, party tss.PartyID) SessionDescriptor {
	return SessionDescriptor{
		Protocol: in.Protocol(), Kind: RunKeygen, SessionID: in.SessionID(), Party: party, PlanDigest: make([]byte, 32),
	}
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
