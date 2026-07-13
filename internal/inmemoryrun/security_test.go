package inmemoryrun

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

func TestRouteClearsConsumedAndInternallyQueuedPayloadsOnFailure(t *testing.T) {
	t.Parallel()
	parties := tss.NewPartySet(1, 2)
	security, err := New(parties, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer security.Destroy()

	const (
		firstPayload  tss.PayloadType = "inmemoryrun.test.first"
		secondPayload tss.PayloadType = "inmemoryrun.test.second"
	)
	policies := tss.MustNewPolicySet(
		tss.DeliveryPolicy{
			Protocol:             tss.ProtocolFROSTEd25519,
			Round:                1,
			PayloadType:          firstPayload,
			Mode:                 tss.DeliveryDirect,
			Confidentiality:      tss.ConfidentialityRequired,
			BroadcastConsistency: tss.BroadcastConsistencyNone,
		},
		tss.DeliveryPolicy{
			Protocol:             tss.ProtocolFROSTEd25519,
			Round:                1,
			PayloadType:          secondPayload,
			Mode:                 tss.DeliveryDirect,
			Confidentiality:      tss.ConfidentialityRequired,
			BroadcastConsistency: tss.BroadcastConsistencyNone,
		},
	)
	var sessionID tss.SessionID
	sessionID[31] = 1
	first, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolFROSTEd25519, SessionID: sessionID, Round: 1,
		From: 1, To: 2, PayloadType: firstPayload, Payload: bytes.Repeat([]byte{0x41}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolFROSTEd25519, SessionID: sessionID, Round: 1,
		From: 2, To: 1, PayloadType: secondPayload, Payload: bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("injected route failure")
	err = security.Route([]tss.Envelope{first}, parties, policies, func(_ tss.PartyID, inbound tss.InboundEnvelope) ([]tss.Envelope, error) {
		switch inbound.PayloadType() {
		case firstPayload:
			return []tss.Envelope{second}, nil
		case secondPayload:
			return nil, wantErr
		default:
			return nil, errors.New("unexpected payload type")
		}
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Route error = %v, want %v", err, wantErr)
	}
	if !allZero(first.Payload) {
		t.Fatal("consumed input payload was not cleared")
	}
	if !allZero(second.Payload) {
		t.Fatal("internally queued payload was not cleared after failure")
	}
}

func allZero(in []byte) bool {
	for _, value := range in {
		if value != 0 {
			return false
		}
	}
	return true
}
