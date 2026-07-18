//go:build integration

package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSAReshareRunsFreshFigure7Epoch(t *testing.T) {
	oldShares, err := runSecpKeygen(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, share := range oldShares {
			share.Destroy()
		}
	}()
	dealers := tss.NewPartySet(1, 3)
	targets := tss.NewPartySet(5, 9, 12)
	testReshareRejectsCrossEpochHandoff(t, oldShares, dealers, targets)
	testReshareRejectsWrongFigure7RID(t, oldShares, dealers, targets)
	newShares, sessions := runCGGMP21ReshareWithDealers(t, oldShares, dealers, targets, 2)
	defer func() {
		for _, share := range newShares {
			share.Destroy()
		}
		for _, session := range sessions {
			session.Destroy()
		}
	}()

	source := oldShares[1].state.Epoch
	for _, party := range targets {
		share := newShares[party]
		if share.state.Epoch == nil {
			t.Fatalf("party %d has no final epoch", party)
		}
		sourceEpochID, ok := share.state.Epoch.SourceEpochIDBytes()
		if !ok || !bytes.Equal(sourceEpochID, source.EpochID) {
			t.Fatalf("party %d final epoch does not bind the exact source epoch", party)
		}
		if share.state.Epoch.SID != source.SID {
			t.Fatalf("party %d changed stable SID lineage", party)
		}
		if share.state.Epoch.RID == source.RID {
			t.Fatalf("party %d reused source RID", party)
		}
		provisional := sessions[party].provisionalIDs[party]
		finalIdentifier, ok := share.state.Epoch.Identifier(party)
		if !ok || bytes.Equal(finalIdentifier, provisional) {
			t.Fatalf("party %d reused the handoff-only identifier in the final epoch", party)
		}
		session := sessions[party]
		if session.auxInfo != nil || session.newPaillier != nil {
			t.Fatalf("party %d retained temporary or Figure 7 secret state", party)
		}
		for dealer, data := range session.dealerData {
			if data.share != nil {
				t.Fatalf("party %d retained temporary share from dealer %d", party, dealer)
			}
		}
		for target, data := range session.newPartyData {
			if data.paillierPub.PublicKey != nil || data.ringPedersen.Params != nil || data.factorProof != nil || data.factorKey != nil {
				t.Fatalf("party %d retained temporary handoff auxiliary material for target %d", party, target)
			}
		}
	}

	for _, dealer := range dealers {
		session := sessions[dealer]
		if !session.completed || session.aborted {
			t.Fatalf("dealer-only party %d did not wait for and accept the target confirmation set", dealer)
		}
		if share, ok := session.KeyShare(); ok || share != nil {
			t.Fatalf("dealer-only party %d produced a target KeyShare", dealer)
		}
	}
	for party, share := range oldShares {
		if err := share.ValidateWithLimits(testLimits()); err != nil {
			t.Fatalf("source share %d was weakened or consumed by reshare: %v", party, err)
		}
	}
}

func testReshareRejectsCrossEpochHandoff(t *testing.T, oldShares map[tss.PartyID]*KeyShare, dealers, targets tss.PartySet) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey: oldShares[1], SessionID: sessionID, DealerParties: dealers,
		NewParties: targets, NewThreshold: 2, Limits: testLimitsPtr(), SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	otherEpoch := plan.state.SourceEpoch.Clone()
	otherEpoch.AuxiliaryDigest[0] ^= 1
	otherEpoch.EpochID = otherEpoch.computeID()
	otherPlan := cloneResharePlan(plan)
	otherPlan.state.SourceEpoch = otherEpoch
	otherPlan.state.SourceEpochID = bytes.Clone(otherEpoch.EpochID)
	if err := otherPlan.ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("build alternate source epoch plan: %v", err)
	}
	sender, out, err := startCGGMP21ReshareReceiver(plan, targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Destroy()
	receiver, _, err := startCGGMP21ReshareReceiver(otherPlan, targets[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Destroy()
	if len(out) == 0 || out[0].PayloadType != payloadReshareReceiverMaterial {
		t.Fatal("source epoch sender omitted temporary receiver material")
	}
	produced, err := receiver.Handle(testutil.DeliverEnvelope(out[0]))
	if err == nil || !errors.Is(err, tss.ErrPlanHashMismatch) {
		t.Fatalf("cross-epoch handoff error = %v, want plan mismatch", err)
	}
	if len(produced) != 0 || receiver.newShare != nil {
		t.Fatal("cross-epoch handoff emitted effects or installed a KeyShare")
	}
	if data := receiver.newPartyData[targets[0]]; data != nil && data.paillierPub.PublicKey != nil {
		t.Fatal("cross-epoch handoff committed receiver material")
	}
}

func testReshareRejectsWrongFigure7RID(t *testing.T, oldShares map[tss.PartyID]*KeyShare, dealers, targets tss.PartySet) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey: oldShares[1], SessionID: sessionID, DealerParties: dealers,
		NewParties: targets, NewThreshold: 2, Limits: testLimitsPtr(), SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, queue := startReshareIntegrationSessions(t, oldShares, plan, dealers, targets)
	defer func() {
		for _, session := range sessions {
			session.Destroy()
		}
	}()
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for id, session := range sessions {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if env.PayloadType == payloadAuxInfoProofs && targets.Contains(id) {
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
				out, handleErr := session.Handle(testutil.DeliverEnvelope(mutated))
				if handleErr == nil {
					t.Fatal("reshare Figure 7 accepted a wrong RID")
				}
				if len(out) != 0 || session.newShare != nil {
					t.Fatal("wrong-RID Figure 7 message emitted effects or installed a KeyShare")
				}
				return
			}
			out, handleErr := session.Handle(testutil.DeliverEnvelope(env))
			if handleErr != nil {
				t.Fatalf("deliver %s from %d to %d before wrong-RID mutation: %v", env.PayloadType, env.From, id, handleErr)
			}
			queue = append(queue, out...)
		}
	}
	t.Fatal("reshare never reached Figure 7 proof round")
}

func startReshareIntegrationSessions(
	t *testing.T,
	oldShares map[tss.PartyID]*KeyShare,
	plan *ResharePlan,
	dealers, targets tss.PartySet,
) (map[tss.PartyID]*ReshareSession, []tss.Envelope) {
	t.Helper()
	sessions := make(map[tss.PartyID]*ReshareSession, len(dealers)+len(targets))
	var queue []tss.Envelope
	for _, party := range dealers {
		var session *ReshareSession
		var out []tss.Envelope
		var err error
		if targets.Contains(party) {
			session, out, err = startCGGMP21ReshareOverlap(oldShares[party], plan, nil)
		} else {
			session, out, err = startCGGMP21ReshareDealer(oldShares[party], plan, nil)
		}
		if err != nil {
			t.Fatalf("start dealer %d: %v", party, err)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	for _, party := range targets {
		if dealers.Contains(party) {
			continue
		}
		session, out, err := startCGGMP21ReshareReceiver(plan, party, nil)
		if err != nil {
			t.Fatalf("start receiver %d: %v", party, err)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	return sessions, queue
}
