//go:build integration

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire/wireutil"
)

func FuzzCGGMP21EnvelopeValidateBasic(f *testing.F) {
	sessionID := fuzzSessionID()
	seed := envelope(
		tss.ThresholdConfig{Threshold: 2, Parties: []tss.PartyID{1, 2}, Self: 1, SessionID: sessionID},
		1,
		1,
		0,
		payloadSignPartial,
		[]byte(`{"s":"AQ==","presign_transcript":"Ag=="}`),
		false,
	)
	encoded, err := seed.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"protocol":"cggmp21-secp256k1","version":1,"round":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var env tss.Envelope
		if err := env.UnmarshalBinary(data); err != nil {
			return
		}
		_ = env.ValidateBasic(protocol, sessionID, []tss.PartyID{1, 2})
		again, err := env.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, again) {
			t.Fatal("envelope did not remarshal deterministically")
		}
	})
}

func FuzzCGGMP21BlameEvidenceUnmarshal(f *testing.F) {
	sessionID := fuzzSessionID()
	env := envelope(
		tss.ThresholdConfig{Threshold: 2, Parties: []tss.PartyID{1, 2}, Self: 1, SessionID: sessionID},
		1,
		1,
		0,
		payloadPresignRound1,
		[]byte(`{"gamma":"AQ=="}`),
		false,
	)
	evidence, err := tss.NewBlameEvidence(env, tss.EvidenceKindPresignRound1, "fuzz seed", []tss.EvidenceField{
		rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash([]tss.PartyID{1, 2}, partySetHashLabel)),
	})
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"version":1,"protocol":"cggmp21-secp256k1"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := tss.UnmarshalBlameEvidence(data)
		if err != nil {
			return
		}
		_ = VerifyBlameEvidence(data, EvidenceContext{
			SessionID: decoded.SessionID,
			Parties:   []tss.PartyID{1, 2},
			Signers:   []tss.PartyID{1, 2},
		})
		again, err := decoded.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, again) {
			t.Fatal("blame evidence did not remarshal deterministically")
		}
	})
}

func FuzzCGGMP21PresignRound1Decode(f *testing.F) {
	share := secpKeygen(f, 1, 1)[1]
	sessionID := fuzzSessionID()
	_, out, err := StartPresign(share, sessionID, []tss.PartyID{1})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(out[0].Payload)
	f.Add([]byte(`{"gamma":"AQ==","enc_k":"Ag=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := unmarshalPresignRound1Payload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, payload, marshalPresignRound1Payload, unmarshalPresignRound1Payload)
	})
}

func FuzzCGGMP21SignPartialDecode(f *testing.F) {
	seed, err := marshalSignPartialPayload(signPartialPayload{
		S:                 scalarBytes(big.NewInt(1)),
		PresignTranscript: make([]byte, sha256.Size),
		PresignContext:    bytes.Repeat([]byte{1}, sha256.Size),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"s":"AQ==","presign_transcript":"Ag=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := unmarshalSignPartialPayload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, payload, marshalSignPartialPayload, unmarshalSignPartialPayload)
	})
}
