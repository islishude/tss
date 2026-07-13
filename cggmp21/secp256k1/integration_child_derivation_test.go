//go:build integration

package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/tssrun"
)

func TestThresholdECDSAChildDerivationRunsFreshFigure7AndPresigns(t *testing.T) {
	shares, err := runSecpKeygen(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyChildTestShares(shares)

	parties := tss.NewPartySet(1, 2)
	parentBinding, stores := installChildTestParents(t, shares, "child-parent", "parent-generation-1")
	plan := newChildIntegrationPlan(t, shares[1], parentBinding, "derived-child", "child-generation-1", tss.DerivationPath{7, 11})
	snapshot, ok := plan.Snapshot()
	if !ok {
		t.Fatal("missing child derivation plan snapshot")
	}
	defer snapshot.Derivation.Destroy()

	sessions, queue := startChildIntegrationSessions(t, shares, stores, plan)
	defer destroyChildTestSessions(sessions)
	deliverChildIntegrationMessages(t, sessions, parties, queue)

	planHash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(planHash)
	children := make(map[tss.PartyID]*KeyShare, len(parties))
	childBindings := make(map[tss.PartyID]tssrun.GenerationBinding, len(parties))
	defer destroyChildTestShares(children)
	for _, party := range parties {
		session := sessions[party]
		binding, installed := session.InstalledBinding()
		if !installed || !session.Completed() {
			t.Fatalf("party %d did not durably install the child generation: meta=%+v aux=%t pending=%t confirmations=%d accepted=%d", party, session.ResultMetadata(), session.auxInfo != nil, session.pending != nil, len(session.confirmations), len(session.accepted))
		}
		if binding.KeyID != snapshot.TargetKeyID || binding.KeyGeneration != snapshot.TargetKeyGeneration ||
			binding.KeyID == parentBinding.KeyID || binding.EpochID == parentBinding.EpochID {
			t.Fatalf("party %d installed invalid child binding %+v", party, binding)
		}
		if session.auxInfo != nil || session.pending != nil || len(session.confirmations) != 0 {
			t.Fatalf("party %d retained child Figure 7 secret state", party)
		}
		record, err := stores[party].LoadCurrentGeneration(context.Background(), binding.KeyID)
		if err != nil {
			t.Fatalf("load child generation for party %d: %v", party, err)
		}
		if record.Binding != binding || record.Status != tssrun.GenerationCurrent || !bytes.Equal(record.Metadata, planHash) {
			clear(record.Blob)
			clear(record.Metadata)
			t.Fatalf("party %d loaded mismatched child generation", party)
		}
		child := new(KeyShare)
		if err := child.UnmarshalBinaryWithLimits(record.Blob, testLimits()); err != nil {
			clear(record.Blob)
			clear(record.Metadata)
			t.Fatalf("decode child generation for party %d: %v", party, err)
		}
		clear(record.Blob)
		clear(record.Metadata)
		if err := child.ValidateWithLimits(testLimits()); err != nil {
			child.Destroy()
			t.Fatalf("validate child generation for party %d: %v", party, err)
		}
		if child.state.Party != party || child.state.Epoch == nil ||
			child.state.Epoch.SID != snapshot.ChildSID ||
			child.state.Epoch.RID == shares[party].state.Epoch.RID ||
			!bytes.Equal(child.state.PublicKey, snapshot.Derivation.ChildPublicKey) ||
			!bytes.Equal(child.state.ChainCode, snapshot.Derivation.ChildChainCode) ||
			child.state.PaillierProofSessionID != snapshot.SessionID ||
			child.state.PaillierProofDomain != domainLabelChildPaillier ||
			!bytes.Equal(child.state.PlanHash, planHash) {
			child.Destroy()
			t.Fatalf("party %d child does not bind the derivation plan and fresh Figure 7 epoch", party)
		}
		sourceEpochID, present := child.state.Epoch.SourceEpochIDBytes()
		if !present || !bytes.Equal(sourceEpochID, parentBinding.EpochID[:]) {
			clear(sourceEpochID)
			child.Destroy()
			t.Fatalf("party %d child omitted the exact parent epoch", party)
		}
		clear(sourceEpochID)
		parentRecord, err := stores[party].LoadCurrentGeneration(context.Background(), parentBinding.KeyID)
		if err != nil {
			child.Destroy()
			t.Fatalf("reload parent generation for party %d: %v", party, err)
		}
		clear(parentRecord.Blob)
		clear(parentRecord.Metadata)
		if parentRecord.Binding != parentBinding || parentRecord.Status != tssrun.GenerationCurrent {
			child.Destroy()
			t.Fatalf("party %d child derivation consumed or replaced the parent", party)
		}
		children[party] = child
		childBindings[party] = binding
	}

	runChildPresignIntegration(t, children, stores, childBindings, parties, snapshot.TargetKeyID)
}

func TestThresholdECDSAChildDerivationRejectsCrossEpochCommitment(t *testing.T) {
	firstShares, err := runSecpKeygen(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyChildTestShares(firstShares)
	secondShares, err := runSecpKeygen(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyChildTestShares(secondShares)
	if bytes.Equal(firstShares[1].state.Epoch.EpochID, secondShares[1].state.Epoch.EpochID) {
		t.Fatal("independent key generations unexpectedly reused an epoch id")
	}

	firstBinding, firstStores := installChildTestParents(t, firstShares, "cross-epoch-parent", "generation-1")
	secondBinding, secondStores := installChildTestParents(t, secondShares, "cross-epoch-parent", "generation-1")
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	firstPlan := newChildIntegrationPlanWithSession(t, firstShares[1], firstBinding, "cross-epoch-child", "generation-1", tss.DerivationPath{3}, sessionID)
	secondPlan := newChildIntegrationPlanWithSession(t, secondShares[1], secondBinding, "cross-epoch-child", "generation-1", tss.DerivationPath{3}, sessionID)

	sender, out, err := StartChildDerivation(firstPlan, ChildDerivationRun{
		Local: tss.LocalConfig{Self: 1, Rand: testutil.DeterministicReader(8101)},
		Guard: testCGGMP21Guard(1, tss.NewPartySet(1, 2), sessionID), LifecycleStore: firstStores[1],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Destroy()
	receiver, _, err := StartChildDerivation(secondPlan, ChildDerivationRun{
		Local: tss.LocalConfig{Self: 2, Rand: testutil.DeterministicReader(8202)},
		Guard: testCGGMP21Guard(2, tss.NewPartySet(1, 2), sessionID), LifecycleStore: secondStores[2],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Destroy()
	if len(out) == 0 || out[0].PayloadType != payloadAuxInfoCommitment {
		t.Fatal("cross-epoch sender omitted its Figure 7 commitment")
	}
	produced, err := receiver.Handle(testutil.DeliverEnvelope(out[0]))
	if err == nil || !errors.Is(err, errPlanHashMismatch) {
		t.Fatalf("cross-epoch child commitment error = %v, want plan mismatch", err)
	}
	if len(produced) != 0 || receiver.pending != nil || receiver.Completed() {
		t.Fatal("cross-epoch commitment emitted effects or installed a child")
	}
	if _, err := secondStores[2].LoadCurrentGeneration(context.Background(), "cross-epoch-child"); !errors.Is(err, tssrun.ErrGenerationNotCurrent) {
		t.Fatalf("cross-epoch commitment child lookup = %v, want no generation", err)
	}
}

func TestThresholdECDSAChildDerivationRejectsWrongFigure7RID(t *testing.T) {
	shares, err := runSecpKeygen(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyChildTestShares(shares)
	parties := tss.NewPartySet(1, 2)
	parentBinding, stores := installChildTestParents(t, shares, "wrong-rid-parent", "generation-1")
	plan := newChildIntegrationPlan(t, shares[1], parentBinding, "wrong-rid-child", "generation-1", tss.DerivationPath{5})
	sessions, queue := startChildIntegrationSessions(t, shares, stores, plan)
	defer destroyChildTestSessions(sessions)

	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, receiver := range parties {
			if receiver == env.From || (env.To != tss.BroadcastPartyId && env.To != receiver) {
				continue
			}
			if env.PayloadType == payloadAuxInfoProofs {
				mutated := env
				payload, decodeErr := tss.DecodeBinaryWithLimits[auxInfoProofsPayload](mutated.Payload, testLimits())
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				payload.RID[0] ^= 1
				mutated.Payload, decodeErr = payload.MarshalBinaryWithLimits(testLimits())
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				out, handleErr := sessions[receiver].Handle(testutil.DeliverEnvelope(mutated))
				if handleErr == nil || len(out) != 0 || sessions[receiver].pending != nil || sessions[receiver].Completed() {
					t.Fatalf("wrong-RID child Figure 7 result out=%d err=%v", len(out), handleErr)
				}
				if _, loadErr := stores[receiver].LoadCurrentGeneration(context.Background(), "wrong-rid-child"); !errors.Is(loadErr, tssrun.ErrGenerationNotCurrent) {
					t.Fatalf("wrong-RID child lookup = %v, want no generation", loadErr)
				}
				return
			}
			out, handleErr := sessions[receiver].Handle(testutil.DeliverEnvelope(env))
			if handleErr != nil {
				t.Fatalf("deliver %s from %d to %d before wrong-RID mutation: %v", env.PayloadType, env.From, receiver, handleErr)
			}
			queue = append(queue, out...)
		}
	}
	t.Fatal("child derivation never reached the Figure 7 proof round")
}

func installChildTestParents(
	t *testing.T,
	shares map[tss.PartyID]*KeyShare,
	keyID string,
	generation tssrun.KeyGeneration,
) (tssrun.GenerationBinding, map[tss.PartyID]*tssrun.MemoryLifecycleStore) {
	t.Helper()
	epochID, err := tssrun.NewEpochID(shares[1].state.Epoch.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	binding := tssrun.GenerationBinding{KeyID: keyID, KeyGeneration: generation, EpochID: epochID}
	stores := make(map[tss.PartyID]*tssrun.MemoryLifecycleStore, len(shares))
	for party, share := range shares {
		blob, err := share.MarshalBinaryWithLimits(testLimits())
		if err != nil {
			t.Fatalf("marshal parent share %d: %v", party, err)
		}
		store := tssrun.NewMemoryLifecycleStore()
		_, installErr := store.InstallInitialGeneration(context.Background(), binding, blob, share.state.PlanHash)
		clear(blob)
		if installErr != nil {
			t.Fatalf("install parent share %d: %v", party, installErr)
		}
		stores[party] = store
	}
	return binding, stores
}

func newChildIntegrationPlan(
	t *testing.T,
	parent *KeyShare,
	parentBinding tssrun.GenerationBinding,
	targetKeyID string,
	targetGeneration tssrun.KeyGeneration,
	path tss.DerivationPath,
) *ChildDerivationPlan {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return newChildIntegrationPlanWithSession(t, parent, parentBinding, targetKeyID, targetGeneration, path, sessionID)
}

func newChildIntegrationPlanWithSession(
	t *testing.T,
	parent *KeyShare,
	parentBinding tssrun.GenerationBinding,
	targetKeyID string,
	targetGeneration tssrun.KeyGeneration,
	path tss.DerivationPath,
	sessionID tss.SessionID,
) *ChildDerivationPlan {
	t.Helper()
	plan, err := NewChildDerivationPlan(ChildDerivationPlanOption{
		Parent: parent, ParentBinding: parentBinding, SessionID: sessionID,
		Path: path, InvalidChildMode: tss.ErrorOnInvalidChild,
		TargetKeyID: targetKeyID, TargetKeyGeneration: targetGeneration,
		PaillierBits: int(testSecurityParams().MinPaillierBits),
		Limits:       testLimitsPtr(), SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func startChildIntegrationSessions(
	t *testing.T,
	shares map[tss.PartyID]*KeyShare,
	stores map[tss.PartyID]*tssrun.MemoryLifecycleStore,
	plan *ChildDerivationPlan,
) (map[tss.PartyID]*ChildDerivationSession, []tss.Envelope) {
	t.Helper()
	parties := shares[1].state.Parties
	sessions := make(map[tss.PartyID]*ChildDerivationSession, len(parties))
	var queue []tss.Envelope
	for _, party := range parties {
		session, out, err := StartChildDerivation(plan, ChildDerivationRun{
			Local: tss.LocalConfig{Self: party, Rand: testutil.DeterministicReader(int64(8300 + party))},
			Guard: testCGGMP21Guard(party, parties, plan.SessionID()), LifecycleStore: stores[party],
		})
		if err != nil {
			destroyChildTestSessions(sessions)
			t.Fatalf("start child derivation party %d: %v", party, err)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	return sessions, queue
}

func deliverChildIntegrationMessages(
	t *testing.T,
	sessions map[tss.PartyID]*ChildDerivationSession,
	parties tss.PartySet,
	queue []tss.Envelope,
) {
	t.Helper()
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, party := range parties {
			if party == env.From || (env.To != tss.BroadcastPartyId && env.To != party) {
				continue
			}
			out, err := sessions[party].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver child %s from %d to %d: %v", env.PayloadType, env.From, party, err)
			}
			queue = append(queue, out...)
		}
	}
}

func runChildPresignIntegration(
	t *testing.T,
	children map[tss.PartyID]*KeyShare,
	stores map[tss.PartyID]*tssrun.MemoryLifecycleStore,
	bindings map[tss.PartyID]tssrun.GenerationBinding,
	parties tss.PartySet,
	keyID string,
) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testPresignContext()
	ctx.KeyID = keyID
	sessions := make(map[tss.PartyID]*PresignSession, len(parties))
	defer func() {
		for _, session := range sessions {
			session.Destroy()
		}
	}()
	var queue []tss.Envelope
	for _, party := range parties {
		plan, err := NewPresignPlan(PresignPlanOption{
			Key: children[party], SessionID: sessionID, PresignID: sessionID[:], Signers: parties,
			Context: ctx, Limits: testLimitsPtr(), SecurityParams: testSecurityParamsPtr(),
		})
		if err != nil {
			t.Fatalf("construct child presign plan for party %d: %v", party, err)
		}
		session, out, err := StartPresign(plan, PresignRuntime{
			Local: tss.LocalConfig{Self: party, Rand: testutil.DeterministicReader(int64(8400 + party))},
			Guard: testCGGMP21Guard(party, parties, sessionID), LifecycleStore: stores[party], Binding: bindings[party],
		})
		if err != nil {
			t.Fatalf("start child presign party %d: %v", party, err)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, party := range parties {
			if party == env.From || (env.To != tss.BroadcastPartyId && env.To != party) {
				continue
			}
			out, err := sessions[party].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver child presign %s from %d to %d: %v", env.PayloadType, env.From, party, err)
			}
			queue = append(queue, out...)
		}
	}
	for _, party := range parties {
		if _, complete := sessions[party].Presign(); !complete {
			t.Fatalf("fresh child generation could not complete presign for party %d", party)
		}
	}
}

func destroyChildTestShares(shares map[tss.PartyID]*KeyShare) {
	for party, share := range shares {
		if share != nil {
			share.Destroy()
		}
		delete(shares, party)
	}
}

func destroyChildTestSessions(sessions map[tss.PartyID]*ChildDerivationSession) {
	for party, session := range sessions {
		if session != nil {
			session.Destroy()
		}
		delete(sessions, party)
	}
}
