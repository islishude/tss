package tssrun

import (
	"context"

	"github.com/islishude/tss"
)

// Receiver opens raw transport bytes into authenticated inbound envelopes.
// Implementations must only populate ReceiveInfo from transport-verified facts.
type Receiver interface {
	Open(raw []byte, info tss.ReceiveInfo, opts ...tss.OpenOption) (tss.InboundEnvelope, error)
}

// EnvelopeReceiver is the default Receiver implementation backed by
// tss.OpenEnvelope.
type EnvelopeReceiver struct{}

// Open decodes raw wire bytes and binds them to transport-verified facts.
func (EnvelopeReceiver) Open(raw []byte, info tss.ReceiveInfo, opts ...tss.OpenOption) (tss.InboundEnvelope, error) {
	return tss.OpenEnvelope(raw, info, opts...)
}

// DispatchInbound opens raw transport bytes, routes the resulting inbound
// envelope through Dispatcher, and sends any produced outbound envelopes.
func DispatchInbound(ctx context.Context, receiver Receiver, dispatcher *Dispatcher, raw []byte, info tss.ReceiveInfo, opts ...tss.OpenOption) error {
	if receiver == nil {
		receiver = EnvelopeReceiver{}
	}
	in, err := receiver.Open(raw, info, opts...)
	if err != nil {
		return err
	}
	return dispatcher.Dispatch(ctx, in)
}
