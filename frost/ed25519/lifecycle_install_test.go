package ed25519

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

func TestFROSTInstallKeyShareDerivesCanonicalEpoch(t *testing.T) {
	shares := frostKeygen(t, 2, 2)
	defer shares[1].Destroy()
	defer shares[2].Destroy()

	binding1, err := GenerationBindingForKeyShare(shares[1], "frost-key", "gen-1")
	if err != nil {
		t.Fatal(err)
	}
	binding2, err := GenerationBindingForKeyShare(shares[2], "frost-key", "gen-1")
	if err != nil {
		t.Fatal(err)
	}
	if binding1 != binding2 {
		t.Fatal("party-local shares derived different lifecycle epochs")
	}
	store := tssrun.NewMemoryLifecycleStore()
	record, err := InstallKeyShare(context.Background(), store, "frost-key", "gen-1", shares[1])
	if err != nil {
		t.Fatal(err)
	}
	if record.Binding != binding1 || record.Status != tssrun.GenerationCurrent {
		t.Fatal("installed FROST generation has the wrong binding")
	}
}

func TestFROSTKeygenRunAdmissionDerivesOutputEpochAfterStart(t *testing.T) {
	ctx := context.Background()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	var messages []tss.Envelope
	for _, party := range parties {
		session, out, err := startFROSTKeygen(tss.ThresholdConfig{
			Threshold: 2, Parties: parties, Self: party, SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = session
		messages = append(messages, out...)
	}
	descriptor := sessions[1].Descriptor()
	run := tssrun.RunIntent{
		RunID: "frost-keygen-run", Protocol: tss.ProtocolFROSTEd25519, Kind: tssrun.RunKeygen,
		SessionID: sessionID, Parties: parties, Threshold: 2,
		TargetKeyID: "frost-admitted-key", TargetKeyGeneration: "gen-1",
		PlanDigest: descriptor.PlanDigest,
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
	deliverFROSTKeygenMessages(t, parties, sessions, messages)
	var canonical tssrun.GenerationBinding
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("FROST keygen did not complete for party %d", party)
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
			t.Fatal("FROST parties installed different canonical epochs")
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
