package tssrun

import (
	"context"

	"github.com/islishude/tss"
)

// UnknownSessionPolicy handles an opened inbound envelope without a registered session.
type UnknownSessionPolicy interface {
	OnUnknownEnvelope(ctx context.Context, in tss.InboundEnvelope) error
}

// DispatchResult owns the exact outbound effects produced by one accepted
// inbound envelope. The caller persists this value before transport delivery
// and calls Destroy after durable ownership transfers.
type DispatchResult struct {
	Session     SessionDescriptor
	InputDigest tss.EnvelopeDigest
	Outbox      []tss.Envelope
}

// Clone returns a deep independent result.
func (r DispatchResult) Clone() DispatchResult {
	out := DispatchResult{Session: r.Session.Clone(), InputDigest: r.InputDigest}
	if len(r.Outbox) != 0 {
		out.Outbox = make([]tss.Envelope, len(r.Outbox))
		for i := range r.Outbox {
			out.Outbox[i] = r.Outbox[i].Clone()
		}
	}
	return out
}

// Destroy clears caller-owned payload and signature bytes.
func (r *DispatchResult) Destroy() {
	if r == nil {
		return
	}
	for i := range r.Outbox {
		clear(r.Outbox[i].Payload)
		clear(r.Outbox[i].SenderSignature)
		r.Outbox[i] = tss.Envelope{}
	}
	clear(r.Session.PlanDigest)
	*r = DispatchResult{}
}

// Dispatcher routes opened inbound envelopes to registered local sessions.
// It never sends effects; callers must durably persist DispatchResult.Outbox
// before handing those envelopes to a transport.
type Dispatcher struct {
	Self     tss.PartyID
	Registry SessionRegistry
	Unknown  UnknownSessionPolicy
}

// Dispatch routes one inbound envelope and returns its exact caller-owned effects.
func (d *Dispatcher) Dispatch(ctx context.Context, in tss.InboundEnvelope) (DispatchResult, error) {
	if d == nil || d.Registry == nil || d.Self == 0 {
		return DispatchResult{}, ErrInvalidSessionKey
	}
	key := SessionKey{Protocol: in.Protocol(), SessionID: in.SessionID(), Party: d.Self}
	session, ok, err := d.Registry.Lookup(ctx, key)
	if err != nil {
		return DispatchResult{}, err
	}
	if !ok {
		unknown := d.Unknown
		if unknown == nil {
			unknown = RejectUnknownSession{}
		}
		return DispatchResult{}, unknown.OnUnknownEnvelope(ctx, in)
	}
	switch session.Status() {
	case SessionSucceeded:
		return DispatchResult{}, ErrRunCompleted
	case SessionAborted:
		return DispatchResult{}, ErrRunAborted
	case SessionCommitPending:
		return DispatchResult{}, ErrLifecycleCommitPending
	case SessionClosePending:
		return DispatchResult{}, ErrSessionClosePending
	case SessionClosed:
		return DispatchResult{}, ErrSessionClosed
	}
	out, err := session.Handle(ctx, in)
	if err != nil {
		rejected := DispatchResult{Outbox: out}
		rejected.Destroy()
		return DispatchResult{}, err
	}
	return DispatchResult{
		Session:     session.Descriptor(),
		InputDigest: in.Digest(),
		Outbox:      out,
	}, nil
}
