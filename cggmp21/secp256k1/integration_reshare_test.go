//go:build integration

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSAReshareInvalidShareCarriesEvidence(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	plan, err := NewResharePlan(ResharePlanOption{OldKey: shares[1], SessionID: sessionID, DealerParties: parties, NewParties: parties, NewThreshold: 2, Limits: testLimitsPtr()})
	if err != nil {
		t.Fatal(err)
	}
	session, out1, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2, out2, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	dealer2Out, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(dealer2Out) < 2 {
		t.Fatalf("dealer 2 emitted %d messages, want commitment and share", len(dealer2Out))
	}
	if _, err := session.Handle(testutil.DeliverEnvelope(dealer2Out[0])); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalReshareSharePayload(dealer2Out[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Proof.TranscriptHash[0] ^= 1
	dealer2Out[1].Payload, err = marshalReshareSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Handle(testutil.DeliverEnvelope(dealer2Out[1]))
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSAReshareInvalidCommitmentCarriesEvidence(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 2)
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey: shares[1], SessionID: sessionID, DealerParties: parties,
		NewParties: parties, NewThreshold: 2, Limits: testLimitsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2, _, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	var commitment tss.Envelope
	for _, env := range out2 {
		if env.PayloadType == payloadReshareDealerCommitments {
			commitment = env
			break
		}
	}
	if commitment.Payload == nil {
		t.Fatal("dealer 2 omitted reshare commitments")
	}
	payload, err := tss.DecodeBinaryValueWithLimits[reshareDealerCommitmentsPayload](commitment.Payload, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	payload.Commitments[0], err = secp.PointBytes(secp.G)
	if err != nil {
		t.Fatal(err)
	}
	commitment.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, err = session1.Handle(testutil.DeliverEnvelope(commitment))
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Blame == nil || !protocolErr.Blame.Parties.Contains(2) {
		t.Fatalf("invalid reshare commitment = %v, want public blame for party 2", err)
	}
	if err := VerifyBlameEvidence(protocolErr.Blame.Evidence, EvidenceContext{SessionID: sessionID, Parties: parties}); err != nil {
		t.Fatalf("verify reshare commitment evidence: %v", err)
	}
}

func TestThresholdECDSAReshareRejectsShareBeforeCommitments(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	plan, err := NewResharePlan(ResharePlanOption{OldKey: shares[1], SessionID: sessionID, DealerParties: parties, NewParties: parties, NewThreshold: 2, Limits: testLimitsPtr()})
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2, _, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	dealer2Out, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(dealer2Out) < 2 {
		t.Fatalf("dealer 2 emitted %d messages, want commitment and share", len(dealer2Out))
	}
	var commitment, share tss.Envelope
	for _, env := range dealer2Out {
		switch env.PayloadType {
		case payloadReshareDealerCommitments:
			commitment = env
		case payloadReshareShare:
			if env.To == 1 {
				share = env
			}
		}
	}
	if commitment.Payload == nil || share.Payload == nil {
		t.Fatal("missing dealer 2 commitment or share")
	}
	if _, err := session1.Handle(testutil.DeliverEnvelope(share)); err == nil {
		t.Fatal("accepted reshare share before dealer commitments")
	}
	if session1.dealerData[2].share != nil {
		t.Fatal("early reshare share mutated dealer state")
	}
	if _, err := session1.Handle(testutil.DeliverEnvelope(commitment)); err != nil {
		t.Fatal(err)
	}
	if _, err := session1.Handle(testutil.DeliverEnvelope(share)); err != nil {
		t.Fatalf("reshare share retry after commitments: %v", err)
	}
}

func TestThresholdECDSAReshareOutboundFailureLeavesStateAndReplayUncommitted(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 2)
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey: shares[1], SessionID: sessionID, DealerParties: parties,
		NewParties: parties, NewThreshold: 2, Limits: testLimitsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session1, _, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session1.Destroy()
	session2, out2, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session2.Destroy()

	originalSigner := session1.cfg.EnvelopeSigner
	session1.cfg.EnvelopeSigner = failingPresignEnvelopeSigner{}
	if out, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil || len(out) != 0 {
		t.Fatalf("reshare outbound construction failure = out:%d err:%v", len(out), err)
	}
	peer := session1.newPartyData[2]
	if peer.paillierPub.PublicKey != nil || session1.dealerSent || session1.factorProofsSent {
		t.Fatal("reshare outbound construction failure mutated accepted state")
	}

	session1.cfg.EnvelopeSigner = originalSigner
	if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatalf("retry after reshare outbound construction failure: %v", err)
	}
	if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); !errors.Is(err, tss.ErrDuplicateMessage) {
		t.Fatalf("accepted reshare duplicate = %v, want ErrDuplicateMessage", err)
	}
}

func TestThresholdECDSAReshareFactorProofMayPrecedeReceiverBroadcast(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 2)
	parties := tss.NewPartySet(1, 2)

	for _, tc := range []struct {
		name     string
		conflict bool
	}{
		{name: "matching broadcast"},
		{name: "conflicting broadcast", conflict: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewResharePlan(ResharePlanOption{OldKey: shares[1], SessionID: sessionID, DealerParties: parties, NewParties: parties, NewThreshold: 2, Limits: testLimitsPtr()})
			if err != nil {
				t.Fatal(err)
			}
			session1, out1, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			session2, out2, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			from2, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
			if err != nil {
				t.Fatal(err)
			}
			var factor tss.Envelope
			for _, env := range from2 {
				if env.PayloadType == payloadReshareFactorProof && env.To == 1 {
					factor = env
					break
				}
			}
			if factor.Payload == nil {
				t.Fatal("receiver 2 omitted factor proof for receiver 1")
			}
			if _, err := session1.Handle(testutil.DeliverEnvelope(factor)); err != nil {
				t.Fatalf("early factor proof: %v", err)
			}
			if data := session1.newPartyData[2]; data.factorProof == nil || data.factorKey == nil || data.paillierPub.PublicKey != nil {
				t.Fatal("early factor proof was not retained independently of receiver material")
			}

			receiverMaterial := out2[0].Clone()
			if tc.conflict {
				payload, err := tss.DecodeBinaryValueWithLimits[reshareReceiverMaterialPayload](receiverMaterial.Payload, testLimits())
				if err != nil {
					t.Fatal(err)
				}
				for {
					payload.PaillierPublicKey.N.Add(payload.PaillierPublicKey.N, big.NewInt(4))
					payload.PaillierPublicKey.G.Add(payload.PaillierPublicKey.N, big.NewInt(1))
					payload.PaillierPublicKey.NSquared.Mul(payload.PaillierPublicKey.N, payload.PaillierPublicKey.N)
					if payload.PaillierPublicKey.Validate() == nil {
						break
					}
				}
				receiverMaterial.Payload, err = payload.MarshalBinaryWithLimits(testLimits())
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = session1.Handle(testutil.DeliverEnvelope(receiverMaterial))
			if tc.conflict {
				var protocolErr *tss.ProtocolError
				if !errors.As(err, &protocolErr) || protocolErr.Blame == nil {
					t.Fatalf("conflicting receiver material = %v, want blame", err)
				}
				evidence, decodeErr := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
				if decodeErr != nil || evidence.Kind != tss.EvidenceKindPaillierAux {
					t.Fatalf("conflicting receiver evidence = %#v, %v", evidence, decodeErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("matching receiver material after factor proof: %v", err)
			}
			if session1.newPartyData[2].paillierPub.PublicKey == nil {
				t.Fatal("matching receiver material was not stored")
			}
		})
	}
}

func TestThresholdECDSAReshareMalformedFactorProofCarriesPaillierEvidence(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 2)
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewResharePlan(ResharePlanOption{OldKey: shares[1], SessionID: sessionID, DealerParties: parties, NewParties: parties, NewThreshold: 2, Limits: testLimitsPtr()})
	if err != nil {
		t.Fatal(err)
	}
	session1, out1, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2, _, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	from2, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	var factor tss.Envelope
	for _, env := range from2 {
		if env.PayloadType == payloadReshareFactorProof && env.To == 1 {
			factor = env
			break
		}
	}
	if factor.Payload == nil {
		t.Fatal("receiver 2 omitted factor proof for receiver 1")
	}
	malformed := factor.Clone()
	malformed.Payload = append(bytes.Clone(malformed.Payload), 0)
	out, err := session1.Handle(testutil.DeliverEnvelope(malformed))
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeInvalidMessage || protocolErr.Blame == nil || len(out) != 0 {
		t.Fatalf("malformed factor proof = out:%d err:%v, want blamed invalid-message", len(out), err)
	}
	evidence, decodeErr := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
	if decodeErr != nil || evidence.Kind != tss.EvidenceKindPaillierAux || evidence.From != 2 {
		t.Fatalf("malformed factor evidence = %#v, %v", evidence, decodeErr)
	}
	if data := session1.newPartyData[2]; data.factorProof != nil || data.factorKey != nil {
		t.Fatal("malformed factor proof mutated receiver state")
	}
}

func TestThresholdECDSAReshareKeyShareValidationBindsPlanHash(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	newShares, _ := runCGGMP21ReshareWithDealers(t, shares, tss.NewPartySet(1, 2), tss.NewPartySet(3, 4), 2)
	share := cloneKeyShareValue(newShares[3])
	meta := mustKeyShareMetadata(t, share)
	if len(meta.ResharePlanHash) != sha256.Size {
		t.Fatalf("got reshare plan hash length %d, want %d", len(meta.ResharePlanHash), sha256.Size)
	}
	share.state.ResharePlanHash[0] ^= 1
	if err := share.ValidateWithLimits(testLimits()); err == nil {
		t.Fatal("Validate accepted reshare key share with tampered plan hash")
	}
}

func TestThresholdECDSAReshareOldOnlyDealersWaitForConfirmations(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	dealers := tss.NewPartySet(1, 2)
	newParties := tss.NewPartySet(3, 4)
	plan, err := NewResharePlan(ResharePlanOption{OldKey: shares[1], SessionID: sessionID, DealerParties: dealers, NewParties: newParties, NewThreshold: 2, Limits: testLimitsPtr()})
	if err != nil {
		t.Fatal(err)
	}
	allParties := tss.NewPartySet(1, 2, 3, 4)
	sessions := make(map[tss.PartyID]*ReshareSession, len(allParties))
	queue := make([]tss.Envelope, 0)
	for _, id := range dealers {
		session, out, err := startCGGMP21ReshareDealer(shares[id], plan, nil)
		if err != nil {
			t.Fatalf("start dealer %d: %v", id, err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	for _, id := range newParties {
		session, out, err := startCGGMP21ReshareReceiver(plan, id, nil)
		if err != nil {
			t.Fatalf("start receiver %d: %v", id, err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}

	type skippedConfirmation struct {
		to  tss.PartyID
		env tss.Envelope
	}
	var skipped []skippedConfirmation
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for id, session := range sessions {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if env.PayloadType == payloadKeygenConfirmation && !session.isReceiver {
				skipped = append(skipped, skippedConfirmation{to: id, env: env})
				continue
			}
			out, err := session.Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
	if len(skipped) == 0 {
		t.Fatal("test did not skip any receiver confirmations")
	}
	for _, id := range dealers {
		if sessions[id].Completed() {
			t.Fatalf("old-only dealer %d completed before receiver confirmations", id)
		}
	}
	for _, item := range skipped {
		if _, err := sessions[item.to].Handle(testutil.DeliverEnvelope(item.env)); err != nil {
			t.Fatalf("deliver skipped confirmation from %d to %d: %v", item.env.From, item.to, err)
		}
	}
	for _, id := range dealers {
		if !sessions[id].Completed() {
			t.Fatalf("old-only dealer %d did not complete after receiver confirmations", id)
		}
		if share, ok := sessions[id].KeyShare(); ok || share != nil {
			t.Fatalf("old-only dealer %d produced a replacement key share", id)
		}
	}
}

// TestThresholdECDSAReshareMembershipChange verifies that reshare preserves the
// group public key across add-party, remove-party, threshold-change, and
// disjoint-dealer-subset scenarios.
func TestThresholdECDSAReshareMembershipChange(t *testing.T) {
	oldShareFixtures := map[fixtureKey]map[tss.PartyID]*KeyShare{
		{threshold: 2, n: 2}: CachedKeygenShares(t, 2, 2),
		{threshold: 2, n: 3}: CachedKeygenShares(t, 2, 3),
	}

	tests := []struct {
		name          string
		oldKey        fixtureKey
		newParties    tss.PartySet
		newThreshold  int
		dealerParties tss.PartySet // nil means all old parties
		signers       tss.PartySet
		removedParty  tss.PartyID // party expected to be removed (0 = none)
		verifySigning bool
		assert        func(t *testing.T, newShares map[tss.PartyID]*KeyShare, sessions map[tss.PartyID]*ReshareSession)
	}{
		{
			name:         "add party 2-of-3 to 2-of-4",
			newParties:   tss.NewPartySet(1, 2, 3, 4),
			newThreshold: 2,
			signers:      tss.NewPartySet(2, 4),
		},
		{
			name:          "remove party 2-of-3 to 2-of-2",
			newParties:    tss.NewPartySet(1, 3),
			newThreshold:  2,
			signers:       tss.NewPartySet(1, 3),
			removedParty:  2,
			verifySigning: true,
		},
		{
			name:         "threshold increase 2-of-2 to 3-of-3",
			oldKey:       fixtureKey{threshold: 2, n: 2},
			newParties:   tss.NewPartySet(1, 2, 3),
			newThreshold: 3,
			signers:      tss.NewPartySet(1, 2, 3),
		},
		{
			name:          "disjoint dealer subset 2-of-3 to 2-of-3",
			newParties:    tss.NewPartySet(4, 5, 6),
			newThreshold:  2,
			dealerParties: tss.NewPartySet(1, 3),
			signers:       tss.NewPartySet(4, 6),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			oldKey := tc.oldKey
			if oldKey == (fixtureKey{}) {
				oldKey = fixtureKey{threshold: 2, n: 3}
			}
			oldFixture := oldShareFixtures[oldKey]
			if oldFixture == nil {
				t.Fatalf("missing old key fixture for %d-of-%d", oldKey.threshold, oldKey.n)
			}
			oldShares := tss.CloneMap(oldFixture)
			oldPub := mustKeySharePublicKey(t, oldShares[1])

			var newShares map[tss.PartyID]*KeyShare
			var sessions map[tss.PartyID]*ReshareSession

			if tc.dealerParties != nil {
				newShares, sessions = runCGGMP21ReshareWithDealers(t, oldShares, tc.dealerParties, tc.newParties, tc.newThreshold)
			} else {
				newShares, sessions = runCGGMP21Reshare(t, oldShares, tc.newParties, tc.newThreshold)
			}

			// Verify new share count matches new party count.
			if len(newShares) != len(tc.newParties) {
				t.Fatalf("got %d new shares, want %d", len(newShares), len(tc.newParties))
			}

			// Verify public key preserved for all new parties.
			for _, id := range tc.newParties {
				if !bytes.Equal(mustKeySharePublicKey(t, newShares[id]), oldPub) {
					t.Fatalf("party %d public key changed after reshare", id)
				}
			}

			// Verify removed party is excluded.
			if tc.removedParty != 0 {
				if _, ok := newShares[tc.removedParty]; ok {
					t.Fatalf("removed party %d received a new key share", tc.removedParty)
				}
				if share, ok := sessions[tc.removedParty].KeyShare(); ok || share != nil {
					t.Fatalf("removed party %d session produced a key share", tc.removedParty)
				}
			}

			if !tc.verifySigning {
				return
			}

			// Sign and verify with a representative selected signer subset.
			digest := sha256.Sum256([]byte("reshare " + tc.name))
			pub, sig, err := SignDigest(digest[:], collectShares(t, newShares, tc.signers))
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyDigest(pub, digest[:], sig) {
				t.Fatal("signature after reshare did not verify")
			}
			if !bytes.Equal(pub, oldPub) {
				t.Fatal("reshare changed group public key")
			}
		})
	}
}

// collectShares returns key shares for the given party IDs.
func collectShares(t *testing.T, shares map[tss.PartyID]*KeyShare, ids tss.PartySet) []*KeyShare {
	t.Helper()
	out := make([]*KeyShare, 0, len(ids))
	for _, id := range ids {
		share, ok := shares[id]
		if !ok {
			t.Fatalf("party %d missing from new shares", id)
		}
		out = append(out, share)
	}
	return out
}
