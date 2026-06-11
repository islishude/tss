//go:build integration || vectorgen

package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"testing"
)

func TestThresholdECDSAKeygenHDChainCode(t *testing.T) {
	runLimitedIntegration(t)

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygenWithOptions(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: sessionID}, KeygenOptions{EnableHD: true})
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
		if len(share.ChainCode) != 32 {
			t.Fatalf("party %d missing chain code", id)
		}
	}
}

func TestThresholdECDSAKeygenPaillierPublicKeyMismatchRejected(t *testing.T) {
	runLimitedIntegration(t)

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	kg1.SetGuard(testCGGMP21Guard(1, tss.PartySet(parties), sessionID))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierPublicKey, err = kg1.paillier.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected keygen Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, EvidenceContext{Parties: parties})
	}
}

func TestThresholdECDSAKeyShareRoundTrip(t *testing.T) {
	runLimitedIntegration(t)

	shares := CachedKeygenShares(t, 2, 3, false)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.PublicKey) != string(shares[1].PublicKey) {
		t.Fatal("public key mismatch after round trip")
	}
}
