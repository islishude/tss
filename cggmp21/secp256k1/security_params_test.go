package secp256k1

import (
	"math/bits"
	"testing"

	"github.com/islishude/tss"
)

func TestCGGMP21Figure28RangeCoversSignerAggregation(t *testing.T) {
	t.Parallel()
	params := testSecurityParams()
	base := max(params.EllPrime, params.Ell+params.Ell)
	plaintextRange := params.DecPlaintextRange()
	if plaintextRange < base {
		t.Fatal("Figure 28 plaintext range does not cover a product of two curve scalars")
	}
	carryBits := plaintextRange - base
	requiredCarryBits := uint32(bits.Len(uint(maxCGGMPSigners - 1)))
	if carryBits < requiredCarryBits {
		t.Fatalf("Figure 28 aggregation slack is %d bits, need at least %d bits for %d signers", carryBits, requiredCarryBits, maxCGGMPSigners)
	}
}

func TestCGGMP21DefaultsRemainProduction(t *testing.T) {
	t.Parallel()

	if DefaultLimits().Threshold.AllowOneOfOne {
		t.Fatal("production limits allow 1-of-1")
	}
	params := DefaultSecurityParams()
	if err := params.Validate(); err != nil {
		t.Fatalf("production security params are invalid: %v", err)
	}
	if params.MinPaillierBits <= testSecurityParams().MinPaillierBits {
		t.Fatal("production Paillier minimum is not stronger than the test profile")
	}

	sessionID := cggmpPlanTestSession(0x61)
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1),
		Threshold: 1,
	}); err == nil {
		t.Fatal("production keygen plan accepted 1-of-1")
	}
	limits := testLimits()
	testParams := testSecurityParams()
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID:      sessionID,
		Parties:        tss.NewPartySet(1),
		Threshold:      1,
		Limits:         &limits,
		SecurityParams: &testParams,
	}); err != nil {
		t.Fatalf("explicit test parameters rejected 1-of-1: %v", err)
	}
}

func TestCGGMP21KeygenPlanDigestBindsSecurityParams(t *testing.T) {
	t.Parallel()

	limits := testLimits()
	firstParams := testSecurityParams()
	secondParams := firstParams
	secondParams.MinPaillierBits++
	sessionID := cggmpPlanTestSession(0x62)
	option := KeygenPlanOption{
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
		Limits:    &limits,
	}
	option.SecurityParams = &firstParams
	first, err := NewKeygenPlan(option)
	if err != nil {
		t.Fatal(err)
	}
	option.SecurityParams = &secondParams
	second, err := NewKeygenPlan(option)
	if err != nil {
		t.Fatal(err)
	}
	assertDifferentCGGMPPlanDigest(t, "security params", first, second)
}
