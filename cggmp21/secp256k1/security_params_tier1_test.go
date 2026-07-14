//go:build tier1

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestTier1_CGGMP21_TrustedDealer_DefaultValidationRejectsTestProfile(t *testing.T) {
	t.Parallel()

	secretKey, err := ParseSecretKey(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID:      cggmpPlanTestSession(0x66),
		Parties:        tss.NewPartySet(1, 2),
		Threshold:      2,
		PaillierBits:   int(params.MinPaillierBits),
		Limits:         &limits,
		SecurityParams: &params,
	}, bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	if err := plan.Validate(); err == nil {
		t.Fatal("production Validate accepted a test-profile trusted-dealer plan")
	}
	if err := plan.ValidateWithLimits(limits); err != nil {
		t.Fatalf("ValidateWithLimits rejected a test-profile trusted-dealer plan: %v", err)
	}
}
