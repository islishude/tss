package tss

import (
	"bytes"
	"fmt"
)

func ExampleNewSessionID() {
	sessionID, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		panic(err)
	}

	fmt.Println(sessionID.String())
	// Output:
	// 1111111111111111111111111111111111111111111111111111111111111111
}

func ExampleEnvelope_MarshalBinary() {
	sessionID, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x22}, 32)))
	if err != nil {
		panic(err)
	}

	envelope := Envelope{
		Protocol:    "example",
		Version:     Version,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: "example.payload",
		Payload:     []byte("hello"),
	}.WithTranscriptHash()

	encoded, err := envelope.MarshalBinary()
	if err != nil {
		panic(err)
	}
	var decoded Envelope
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		panic(err)
	}

	fmt.Println(decoded.PayloadType, string(decoded.Payload))
	// Output:
	// example.payload hello
}

func ExampleUnmarshalBlameEvidence() {
	sessionID, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)))
	if err != nil {
		panic(err)
	}

	envelope := Envelope{
		Protocol:    "example",
		Version:     Version,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: "example.payload",
		Payload:     []byte("bad partial"),
	}.WithTranscriptHash()
	evidence, err := NewBlameEvidence(envelope, EvidenceKindSignPartial, "invalid partial", []EvidenceField{
		{Key: "public_hash", Value: []byte{1, 2, 3}},
	})
	if err != nil {
		panic(err)
	}

	encoded, err := evidence.MarshalBinary()
	if err != nil {
		panic(err)
	}
	decoded, err := UnmarshalBlameEvidence(encoded)
	if err != nil {
		panic(err)
	}

	fmt.Println(decoded.Kind, decoded.From)
	// Output:
	// sign_partial 1
}
