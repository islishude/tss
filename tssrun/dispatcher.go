package tssrun

import (
	"context"

	"github.com/islishude/tss"
)

// Transport sends outbound envelopes produced by protocol sessions.
type Transport interface {
	SendAll(ctx context.Context, envelopes []tss.Envelope) error
}

// UnknownSessionPolicy handles an opened inbound envelope without a registered session.
type UnknownSessionPolicy interface {
	OnUnknownEnvelope(ctx context.Context, in tss.InboundEnvelope) error
}

// Dispatcher routes opened inbound envelopes to registered local sessions.
type Dispatcher struct {
	Self      tss.PartyID
	Registry  SessionRegistry
	Unknown   UnknownSessionPolicy
	Transport Transport
}

// Dispatch routes one inbound envelope and sends any produced outbox envelopes.
func (d *Dispatcher) Dispatch(ctx context.Context, in tss.InboundEnvelope) error {
	if d == nil || d.Registry == nil || d.Self == 0 {
		return ErrInvalidSessionKey
	}
	key := SessionKey{
		Protocol:  in.Protocol(),
		SessionID: in.SessionID(),
		Party:     d.Self,
	}
	session, ok, err := d.Registry.Lookup(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		unknown := d.Unknown
		if unknown == nil {
			unknown = RejectUnknownSession{}
		}
		return unknown.OnUnknownEnvelope(ctx, in)
	}
	if session.Completed() {
		return ErrRunCompleted
	}
	out, err := session.Handle(in)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		return nil
	}
	if d.Transport == nil {
		return ErrMissingTransport
	}
	return d.Transport.SendAll(ctx, out)
}
