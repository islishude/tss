package secp256k1

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestResharePlanValidateAcceptsDealerSubset(t *testing.T) {
	plan := minimalValidResharePlan(t)
	plan.DealerParties = []tss.PartyID{2}
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !IsDealer(plan, 2) {
		t.Fatal("party 2 should be a dealer")
	}
	if !IsReceiver(plan, 3) {
		t.Fatal("party 3 should be a receiver")
	}
	if IsOverlap(plan, 1) {
		t.Fatal("party 1 should not overlap")
	}
}

func TestResharePlanValidateRejectsWrongOldPublicKey(t *testing.T) {
	plan := minimalValidResharePlan(t)
	plan.OldGroupPublicKey = mustResharePlanPoint(t, 2)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted old commitment/public key mismatch")
	}
}

func TestResharePlanValidateRejectsDealerOutsideOldSet(t *testing.T) {
	plan := minimalValidResharePlan(t)
	plan.DealerParties = []tss.PartyID{3}
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted dealer outside old party set")
	}
}

func TestResharePlanValidateRejectsVerificationShareMismatch(t *testing.T) {
	plan := minimalValidResharePlan(t)
	plan.OldVerificationShares[2] = mustResharePlanPoint(t, 2)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted wrong old verification share")
	}
}

func minimalValidResharePlan(t *testing.T) ResharePlan {
	t.Helper()
	var sessionID tss.SessionID
	sessionID[0] = 1
	publicKey := mustResharePlanPoint(t, 1)
	return ResharePlan{
		SessionID:           sessionID,
		CurveID:             reshareCurveID,
		OldGroupPublicKey:   publicKey,
		OldGroupCommitments: [][]byte{publicKey},
		OldVerificationShares: map[tss.PartyID][]byte{
			1: append([]byte(nil), publicKey...),
			2: append([]byte(nil), publicKey...),
		},
		OldParties:    []tss.PartyID{1, 2},
		OldThreshold:  1,
		DealerParties: []tss.PartyID{1},
		NewParties:    []tss.PartyID{2, 3},
		NewThreshold:  2,
	}
}

func mustResharePlanPoint(t *testing.T, scalar int64) []byte {
	t.Helper()
	out, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(scalar))))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
