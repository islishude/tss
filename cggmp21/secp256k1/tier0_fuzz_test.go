package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire/wireutil"
)

// FuzzFast_EnvelopeValidateBasic fuzzes TLV envelope decoding. The seed
// corpus is constructed manually without any keygen or crypto.
func FuzzFast_EnvelopeValidateBasic(f *testing.F) {
	sessionID := fuzzSessionID()
	seed, err := envelope(
		tss.ThresholdConfig{Threshold: 2, Parties: []tss.PartyID{1, 2}, Self: 1, SessionID: sessionID},
		1,
		1,
		0,
		payloadSignPartial,
		[]byte(`{"s":"AQ==","presign_transcript":"Ag=="}`),
		false,
	)
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := seed.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, data []byte) {
		var env tss.Envelope
		if err := env.UnmarshalBinary(data); err != nil {
			return
		}
		_ = tss.ValidateEnvelopeBasic(env, protocol, sessionID, []tss.PartyID{1, 2})
		again, err := env.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, data) {
			t.Fatal("envelope did not remarshal deterministically")
		}
	})
}

// FuzzFast_BlameEvidenceUnmarshal fuzzes blame evidence decoding. The seed
// uses a manually constructed envelope and evidence without keygen.
func FuzzFast_BlameEvidenceUnmarshal(f *testing.F) {
	sessionID := fuzzSessionID()
	env, err := envelope(
		tss.ThresholdConfig{Threshold: 2, Parties: []tss.PartyID{1, 2}, Self: 1, SessionID: sessionID},
		1,
		1,
		0,
		payloadPresignRound1,
		[]byte(`{"gamma":"AQ=="}`),
		false,
	)
	if err != nil {
		f.Fatal(err)
	}
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
		// Check deterministic remarshaling: marshal → unmarshal → marshal
		// must produce identical bytes. We compare canonical outputs, not
		// the raw fuzz input (which may use different JSON key casing or
		// omit optional fields).
		testutil.AssertDeterministicRoundTrip(t, decoded, (*tss.BlameEvidence).MarshalBinary, tss.UnmarshalBlameEvidence)
	})
}

// FuzzFast_SignPartialDecode fuzzes sign partial payload decoding. The seed
// is constructed manually without any keygen.
func FuzzFast_SignPartialDecode(f *testing.F) {
	seed, err := marshalSignPartialPayload(signPartialPayload{
		S:                   big.NewInt(1),
		PresignTranscript:   make([]byte, sha256.Size),
		PresignContext:      bytes.Repeat([]byte{1}, sha256.Size),
		DigestHash:          make([]byte, sha256.Size),
		PartialEquationHash: make([]byte, sha256.Size),
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

// FuzzFast_PresignUnmarshal fuzzes Presign binary decoding. The seed uses
// a minimal Presign constructed without any keygen.
func FuzzFast_PresignUnmarshal(f *testing.F) {
	presign := minimalCGGMP21Presign(f)
	raw, err := presign.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		presign, err := UnmarshalPresign(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, presign, (*Presign).MarshalBinary, UnmarshalPresign)
	})
}

// FuzzFast_KeygenSharePayloadUnmarshal fuzzes keygen share payload decoding
// using a manually constructed seed (no keygen required).
func FuzzFast_KeygenSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalKeygenSharePayload(keygenSharePayload{Share: big.NewInt(1)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenSharePayload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalKeygenSharePayload, unmarshalKeygenSharePayload)
	})
}

// FuzzFast_PresignRound3PayloadUnmarshal fuzzes presign round 3 payload
// decoding (no keygen required).
func FuzzFast_PresignRound3PayloadUnmarshal(f *testing.F) {
	proof := mustMinimalSignPrepProofForTest(f)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(2))))
	raw, err := marshalPresignRound3Payload(presignRound3Payload{
		Delta:    big.NewInt(1),
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proof,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"delta":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalPresignRound3Payload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalPresignRound3Payload, unmarshalPresignRound3Payload)
	})
}

// FuzzFast_ReshareSharePayloadUnmarshal fuzzes reshare share payload decoding
// (no keygen required).
func FuzzFast_ReshareSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalReshareSharePayload(reshareSharePayload{
		Dealer:               1,
		Receiver:             2,
		Share:                big.NewInt(1),
		DealerCommitmentHash: make([]byte, sha256.Size),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareSharePayload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalReshareSharePayload, unmarshalReshareSharePayload)
	})
}

// FuzzFast_RefreshSharePayloadUnmarshal fuzzes refresh share payload decoding
// (no keygen required).
func FuzzFast_RefreshSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalRefreshSharePayload(refreshSharePayload{Share: big.NewInt(1)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalRefreshSharePayload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalRefreshSharePayload, unmarshalRefreshSharePayload)
	})
}

// FuzzFast_VerifySignPartialInputs fuzzes the verifySignPartial method against
// malformed inputs. It constructs a minimal valid session and feeds random
// payload data.
func FuzzFast_VerifySignPartialInputs(f *testing.F) {
	presign := minimalCGGMP21Presign(f)
	// Create a minimal SignSession.
	s := &SignSession{
		key:     &KeyShare{Party: 1, Parties: []tss.PartyID{1}, Threshold: 1},
		presign: presign,
		digest:  bytes.Repeat([]byte{0xaa}, 32),
		log:     tss.NopLogger(),
	}
	f.Add(mustMinimalSignPrepProofForTest(f))
	f.Add([]byte{0x00})
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// verifySignPartial should never panic on any input.
		p := signPartialPayload{
			S:                   new(big.Int).SetBytes(data),
			PresignTranscript:   presign.TranscriptHash,
			PresignContext:      presign.ContextHash,
			DigestHash:          bytes.Repeat([]byte{0xaa}, 32),
			PartialEquationHash: bytes.Repeat([]byte{0xbb}, 32),
		}
		_, _ = s.verifySignPartial(1, p)
	})
}

// fuzzSessionID returns a deterministic session ID for fuzz seed data.
func fuzzSessionID() tss.SessionID {
	var sessionID tss.SessionID
	for i := range sessionID {
		sessionID[i] = byte(i + 1)
	}
	return sessionID
}
