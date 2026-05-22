package secp256k1

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

func FuzzGG20EnvelopeValidateBasic(f *testing.F) {
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
	f.Add([]byte(`{"protocol":"gg20-secp256k1","version":1,"round":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var env tss.Envelope
		if err := env.UnmarshalBinary(data); err != nil {
			return
		}
		_ = env.ValidateBasic(protocol, sessionID, []tss.PartyID{1, 2})
	})
}

func FuzzGG20BlameEvidenceUnmarshal(f *testing.F) {
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
		rawEvidenceField(evidenceFieldPartiesHash, partySetHash([]tss.PartyID{1, 2})),
	})
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"version":1,"protocol":"gg20-secp256k1"}`))
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
	})
}

func FuzzGG20PresignRound1Decode(f *testing.F) {
	seed, err := json.Marshal(presignRound1Payload{
		Gamma:             []byte{0x02},
		EncK:              []byte{0x01},
		EncKProof:         []byte(`{}`),
		EncKRangeProof:    []byte(`{}`),
		PaillierPublicKey: []byte(`{"n":"3","g":"4"}`),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"gamma":"AQ==","enc_k":"Ag=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var payload presignRound1Payload
		if err := json.Unmarshal(data, &payload); err != nil {
			return
		}
		_, _ = secp.PointFromBytes(payload.Gamma)
		_, _ = pai.UnmarshalPublicKey(payload.PaillierPublicKey)
		_ = sha256.Sum256(payload.EncK)
		_ = sha256.Sum256(payload.EncKProof)
		_ = sha256.Sum256(payload.EncKRangeProof)
	})
}

func FuzzGG20SignPartialDecode(f *testing.F) {
	seed, err := json.Marshal(signPartialPayload{
		S:                 []byte{0x01},
		PresignTranscript: make([]byte, sha256.Size),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"s":"AQ==","presign_transcript":"Ag=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var payload signPartialPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return
		}
		_, _ = secp.ParseScalar(payload.S)
		_ = len(payload.PresignTranscript) == sha256.Size
	})
}

func fuzzSessionID() tss.SessionID {
	var sessionID tss.SessionID
	for i := range sessionID {
		sessionID[i] = byte(i + 1)
	}
	return sessionID
}
