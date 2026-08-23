//go:build integration

package secp256k1

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/tssrun"
)

func TestCGGMP21KeygenRunAdmissionDerivesOutputEpochAfterStart(t *testing.T) {
	ctx := context.Background()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	var messages []tss.Envelope
	for _, party := range parties {
		session, out, err := startCGGMP21Keygen(tss.ThresholdConfig{
			Threshold: 2, Parties: parties, Self: party, SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = session
		messages = append(messages, out...)
	}
	run := tssrun.RunIntent{
		RunID: "cggmp21-keygen-run", Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunKeygen,
		SessionID: sessionID, Parties: parties, Threshold: 2,
		TargetKeyID: "cggmp21-admitted-key", TargetKeyGeneration: "gen-1",
		PlanDigest: sessions[1].Descriptor().PlanDigest,
	}
	runStore := tssrun.NewMemoryRunStore()
	registry := tssrun.NewMemorySessionRegistry()
	if err := runStore.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	for _, party := range parties {
		if err := tssrun.AcceptPlanDigest(ctx, runStore, run, party, run.AcceptanceDigest()); err != nil {
			t.Fatal(err)
		}
		if err := tssrun.RegisterStartedSession(ctx, runStore, registry, run.RunID, party, sessions[party]); err != nil {
			t.Fatal(err)
		}
	}
	deliverKeygenMessages(t, sessions, parties, messages)
	var canonical tssrun.GenerationBinding
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("CGGMP21 keygen did not complete for party %d", party)
		}
		lifecycle := tssrun.NewMemoryLifecycleStore()
		record, err := InstallKeyShareWithLimits(ctx, lifecycle, run.TargetKeyID, run.TargetKeyGeneration, share, testLimits())
		share.Destroy()
		if err != nil {
			t.Fatal(err)
		}
		if canonical == (tssrun.GenerationBinding{}) {
			canonical = record.Binding
		} else if record.Binding != canonical {
			t.Fatal("CGGMP21 parties installed different canonical epochs")
		}
		output := sha256.Sum256(record.Blob)
		if err := runStore.MarkCompleted(ctx, run.RunID, party, tssrun.LocalRunResult{Binding: record.Binding, OutputDigest: output[:]}); err != nil {
			t.Fatal(err)
		}
		if err := sessions[party].Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

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
	if _, err := kg1.Handle(context.Background(), testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	reveal2, err := kg2.Handle(context.Background(), testutil.DeliverEnvelope(out1[0]))
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
	if _, err := kg1.Handle(context.Background(), testutil.DeliverEnvelope(reveal2[0])); err == nil {
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
