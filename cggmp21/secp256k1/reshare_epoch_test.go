package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
)

func TestReshareProvisionalIdentifiersAreDomainBoundAndCollisionFree(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	identifiers := mustReshareProvisionalIdentifiers(t, plan)
	seen := make(map[string]tss.PartyID, len(plan.state.NewParties))
	for _, party := range plan.state.NewParties {
		first := identifiers[party]
		second := mustReshareProvisionalIdentifiers(t, plan)[party]
		if !bytes.Equal(first, second) {
			t.Fatalf("party %d provisional identifier is not deterministic", party)
		}
		if _, err := shamir.IdentifierFromBytes(first); err != nil {
			t.Fatalf("party %d provisional identifier: %v", party, err)
		}
		if other, ok := seen[string(first)]; ok {
			t.Fatalf("parties %d and %d share a provisional identifier", other, party)
		}
		seen[string(first)] = party
		fixed := secp.ScalarFromUint64(uint64(party)).Bytes()
		if bytes.Equal(first, fixed) {
			t.Fatalf("party %d fell back to its transport PartyID as Shamir coordinate", party)
		}
	}

	changed := cloneResharePlan(plan)
	changed.state.SessionID[1] ^= 1
	original := identifiers[plan.state.NewParties[0]]
	differentRun := mustReshareProvisionalIdentifiers(t, changed)[plan.state.NewParties[0]]
	if bytes.Equal(original, differentRun) {
		t.Fatal("provisional identifier did not bind the reshare run session and plan hash")
	}
}

func mustReshareProvisionalIdentifiers(t *testing.T, plan *ResharePlan) map[tss.PartyID][]byte {
	t.Helper()
	planHash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	identifiers, err := deriveReshareProvisionalIdentifiers(
		plan.state.SourceEpoch.SID,
		plan.state.SourceEpochID,
		plan.state.SessionID,
		planHash,
		plan.state.NewParties,
	)
	if err != nil {
		t.Fatal(err)
	}
	return identifiers
}

func TestReshareDealerCommitmentUsesSourceEpochCoordinates(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	session := &ReshareSession{
		plan:          plan,
		dealerParties: plan.state.DealerParties.Clone(),
		newThreshold:  plan.state.NewThreshold,
	}
	dealer := plan.state.DealerParties[0]
	publicShare, ok := plan.state.SourceEpoch.PublicShare(dealer)
	if !ok {
		t.Fatal("missing source epoch public share")
	}
	publicPoint, err := secp.PointFromBytes(publicShare.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	epochLambda, err := epochLagrangeCoefficient(plan.state.SourceEpoch, dealer, plan.state.DealerParties)
	if err != nil {
		t.Fatal(err)
	}
	constant, err := secp.PointBytes(secp.ScalarMult(publicPoint, epochLambda))
	if err != nil {
		t.Fatal(err)
	}
	commitments := [][]byte{constant, mustResharePlanPoint(t, 7)}
	if err := session.validateDealerCommitments(dealer, commitments); err != nil {
		t.Fatalf("epoch-coordinate dealer commitment rejected: %v", err)
	}

	fixedLambda := fixedPartyIDLagrangeOracle(t, dealer, plan.state.DealerParties)
	if fixedLambda.Equal(epochLambda) {
		t.Skip("test hash produced the negligible fixed-coordinate equality")
	}
	commitments[0], err = secp.PointBytes(secp.ScalarMult(publicPoint, fixedLambda))
	if err != nil {
		t.Fatal(err)
	}
	if err := session.validateDealerCommitments(dealer, commitments); err == nil {
		t.Fatal("dealer commitment accepted fixed PartyID interpolation coefficient")
	}
}

// fixedPartyIDLagrangeOracle intentionally models the retired x=PartyID
// coordinate rule. It is test-local so production code cannot accidentally
// regain a fixed-coordinate Shamir helper.
func fixedPartyIDLagrangeOracle(t testing.TB, target tss.PartyID, parties tss.PartySet) secp.Scalar {
	t.Helper()
	if target == tss.BroadcastPartyId {
		t.Fatal("fixed-coordinate oracle target is zero")
	}
	xi := secp.ScalarFromUint64(uint64(target))
	numerator := secp.ScalarOne()
	denominator := secp.ScalarOne()
	seen := make(map[tss.PartyID]struct{}, len(parties))
	found := false
	for _, party := range parties {
		if party == tss.BroadcastPartyId {
			t.Fatal("fixed-coordinate oracle party is zero")
		}
		if _, ok := seen[party]; ok {
			t.Fatalf("fixed-coordinate oracle duplicate party %d", party)
		}
		seen[party] = struct{}{}
		if party == target {
			found = true
			continue
		}
		xj := secp.ScalarFromUint64(uint64(party))
		numerator = secp.ScalarMul(numerator, xj)
		denominator = secp.ScalarMul(denominator, secp.ScalarSub(xj, xi))
	}
	if !found {
		t.Fatalf("fixed-coordinate oracle target %d is missing", target)
	}
	inverse, err := secp.ScalarInvert(denominator)
	if err != nil {
		t.Fatalf("fixed-coordinate oracle denominator: %v", err)
	}
	return secp.ScalarMul(numerator, inverse)
}

func TestNewResharePlanRejectsWrongSourceEpoch(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 2)
	wrong := shares[1].state.Epoch.Clone()
	wrong.AuxiliaryDigest[0] ^= 1
	wrong.EpochID = wrong.computeID()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewResharePlan(ResharePlanOption{
		OldKey:        shares[1],
		SourceEpoch:   wrong,
		SessionID:     sessionID,
		DealerParties: shares[1].state.Parties,
		NewParties:    shares[1].state.Parties,
		NewThreshold:  shares[1].state.Threshold,
		Limits:        testLimitsPtr(),
	})
	if err == nil {
		t.Fatal("NewResharePlan accepted a different source epoch")
	}
}
