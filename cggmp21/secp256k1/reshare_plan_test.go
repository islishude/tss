package secp256k1

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestResharePlanValidateAcceptsDealerSubset(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.OldGroupPublicKey = mustResharePlanPoint(t, 2)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted old commitment/public key mismatch")
	}
}

func TestResharePlanValidateRejectsDealerOutsideOldSet(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.DealerParties = []tss.PartyID{3}
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted dealer outside old party set")
	}
}

func TestResharePlanValidateRejectsVerificationShareMismatch(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.OldVerificationShares[2] = mustResharePlanPoint(t, 2)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted wrong old verification share")
	}
}

func TestResharePlanDigestBindsPublicInputs(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	digest1, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digest2, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest1, digest2) {
		t.Fatal("reshare plan digest is not deterministic")
	}
	mutated := plan
	mutated.ChainCode = bytes.Repeat([]byte{0x42}, 32)
	digest3, err := mutated.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest1, digest3) {
		t.Fatal("reshare plan digest did not change after chain-code mutation")
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

func TestNewResharePlanRejectsEmptyOldParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(&KeyShare{Party: 1, Threshold: 1, Parties: nil}, tss.SessionID{}, nil, []tss.PartyID{1}, 1)
	if err == nil {
		t.Fatal("expected error for empty old parties")
	}
}

func TestNewResharePlanRejectsZeroThreshold(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(&KeyShare{Party: 1, Threshold: 0, Parties: []tss.PartyID{1}}, tss.SessionID{}, []tss.PartyID{1}, []tss.PartyID{2}, 1)
	if err == nil {
		t.Fatal("expected error for zero threshold")
	}
}

func TestNewResharePlanRejectsThresholdExceedsOldParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(&KeyShare{Party: 1, Threshold: 3, Parties: []tss.PartyID{1, 2}}, tss.SessionID{}, []tss.PartyID{1}, []tss.PartyID{2}, 2)
	if err == nil {
		t.Fatal("expected error when threshold > old party count")
	}
}

func TestNewResharePlanRejectsThresholdZeroParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(&KeyShare{Party: 1, Threshold: 1, Parties: []tss.PartyID{1}}, tss.SessionID{}, nil, []tss.PartyID{1}, 1)
	if err == nil {
		t.Fatal("expected error for empty dealer parties")
	}
}

func TestNewResharePlanRejectsNilNewParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(&KeyShare{Party: 1, Threshold: 1, Parties: []tss.PartyID{1}}, tss.SessionID{}, []tss.PartyID{1}, nil, 1)
	if err == nil {
		t.Fatal("expected error for nil new parties")
	}
}

func TestNewResharePlanRejectsInvalidNewThreshold(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(&KeyShare{Party: 1, Threshold: 1, Parties: []tss.PartyID{1}}, tss.SessionID{}, []tss.PartyID{1}, []tss.PartyID{2, 3}, 5)
	if err == nil {
		t.Fatal("expected error when newThreshold > new party count")
	}
}

func TestIsDealerReceiverOverlapFalseForNonMembers(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	if IsDealer(plan, 99) {
		t.Fatal("party 99 should not be a dealer")
	}
	if IsReceiver(plan, 99) {
		t.Fatal("party 99 should not be a receiver")
	}
	if IsOverlap(plan, 99) {
		t.Fatal("party 99 should not be overlap")
	}
}

func TestResharePlanValidateRejectsNilCurveID(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.CurveID = ""
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted empty CurveID")
	}
}
