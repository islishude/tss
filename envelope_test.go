package tss

import "testing"

func TestEnvelopeBinaryRoundTripAndTranscript(t *testing.T) {
	session, err := NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{
		Protocol:    "test",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		To:          2,
		PayloadType: "payload",
		Payload:     []byte("hello"),
	}.WithTranscriptHash()
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateBasic("test", session, []PartyID{1, 2}); err != nil {
		t.Fatal(err)
	}
	decoded.Payload[0] ^= 1
	if err := decoded.ValidateBasic("test", session, []PartyID{1, 2}); err == nil {
		t.Fatal("expected transcript mismatch")
	}
}
