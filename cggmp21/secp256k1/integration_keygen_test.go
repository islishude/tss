//go:build integration

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSAKeygenHDChainCode(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := startCGGMP21KeygenWithPlanOption(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: sessionID}, KeygenPlanOption{})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	deliverKeygenMessages(t, sessions, parties, messages)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		if len(mustKeyShareChainCode(t, share)) != 32 {
			t.Fatalf("party %d missing chain code", id)
		}
	}
}

func TestThresholdECDSAKeygenFigure6RevealMismatchRejected(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	kg1, out1, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	kg2, out2, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kg1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	reveal2, err := kg2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil || len(reveal2) != 1 || reveal2[0].PayloadType != payloadFigure6Reveal {
		t.Fatalf("produce Figure 6 reveal: out=%v err=%v", reveal2, err)
	}
	payload, err := tss.DecodeBinaryWithLimits[figure6RevealPayload](reveal2[0].Payload, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	payload.Decommitment[0] ^= 1
	mutated, err := payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	reveal2[0].Payload = mutated
	if _, err := kg1.Handle(testutil.DeliverEnvelope(reveal2[0])); err == nil {
		t.Fatal("expected Figure 6 reveal mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, EvidenceContext{Parties: parties})
	}
}

func TestThresholdECDSAKeyShareRoundTrip(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tss.DecodeBinary[KeyShare](raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(mustKeySharePublicKey(t, decoded)) != string(mustKeySharePublicKey(t, shares[1])) {
		t.Fatal("public key mismatch after round trip")
	}
}
