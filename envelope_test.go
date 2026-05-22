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

func TestEnvelopeUnmarshalRejectsNonCanonicalEncoding(t *testing.T) {
	var decoded Envelope
	if err := decoded.UnmarshalBinary([]byte(`{"protocol":"test","version":1}`)); err == nil {
		t.Fatal("JSON envelope encoding accepted")
	}
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
		PayloadType: "payload",
	}.WithTranscriptHash()
	raw, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0)
	if err := decoded.UnmarshalBinary(raw); err == nil {
		t.Fatal("envelope with trailing bytes accepted")
	}
}

func FuzzEnvelopeUnmarshalBinary(f *testing.F) {
	session, err := NewSessionID(nil)
	if err != nil {
		f.Fatal(err)
	}
	env := Envelope{
		Protocol:    "test",
		Version:     Version,
		SessionID:   session,
		Round:       1,
		From:        1,
		PayloadType: "payload",
	}.WithTranscriptHash()
	raw, err := env.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"protocol":"test","version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var decoded Envelope
		if err := decoded.UnmarshalBinary(data); err != nil {
			return
		}
		_ = decoded.ValidateBasic("test", session, []PartyID{1, 2})
	})
}
