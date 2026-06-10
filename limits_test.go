package tss

import (
	"testing"
)

// defaultTestThresholdLimits returns conservative fail-closed threshold limits for testing.
func defaultTestThresholdLimits() ThresholdLimits {
	return ThresholdLimits{
		MaxParties:              DefaultMaxParties,
		MaxThreshold:            DefaultMaxThreshold,
		MaxSigners:              DefaultMaxSigners,
		MinProductionThreshold:  2,
		AllowOneOfOne:           false,
		AllowOversizedSignerSet: false,
	}
}

func TestThresholdConfigRejectsTooManyParties(t *testing.T) {
	limits := defaultTestThresholdLimits()
	limits.MaxParties = 4

	cfg := ThresholdConfig{
		Threshold: 1,
		Parties:   []PartyID{1, 2, 3, 4, 5},
		Self:      1,
	}
	if err := cfg.ValidateWithLimits(limits); err == nil {
		t.Fatal("expected error for too many parties")
	}
}

func TestThresholdConfigRejectsTooLargeThreshold(t *testing.T) {
	limits := defaultTestThresholdLimits()
	limits.MaxThreshold = 3

	cfg := ThresholdConfig{
		Threshold: 4,
		Parties:   []PartyID{1, 2, 3, 4},
		Self:      1,
	}
	if err := cfg.ValidateWithLimits(limits); err == nil {
		t.Fatal("expected error for threshold too large")
	}
}

func TestThresholdConfigAllowsOneOfOneOnlyWhenExplicit(t *testing.T) {
	// Default threshold limits are fail-closed: reject 1-of-1.
	cfg := ThresholdConfig{
		Threshold: 1,
		Parties:   []PartyID{1},
		Self:      1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("default limits should reject 1-of-1")
	}

	// Explicit block: AllowOneOfOne=false, MinProductionThreshold=2
	limits := defaultTestThresholdLimits()
	limits.AllowOneOfOne = false
	limits.MinProductionThreshold = 2
	if err := cfg.ValidateWithLimits(limits); err == nil {
		t.Fatal("expected error for 1-of-1 when blocked")
	}

	// Explicit allow with AllowOneOfOne=true and MinProductionThreshold=1
	limits.AllowOneOfOne = true
	limits.MinProductionThreshold = 1
	if err := cfg.ValidateWithLimits(limits); err != nil {
		t.Fatalf("1-of-1 should be allowed when explicitly enabled: %v", err)
	}
}

func TestThresholdConfigRejectsThresholdExceedsParties(t *testing.T) {
	cfg := ThresholdConfig{
		Threshold: 4,
		Parties:   []PartyID{1, 2, 3},
		Self:      1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when threshold exceeds party count")
	}
}

func TestThresholdConfigRejectsZeroPartyID(t *testing.T) {
	cfg := ThresholdConfig{
		Threshold: 1,
		Parties:   []PartyID{0},
		Self:      0,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero party id")
	}
}

func TestThresholdConfigRejectsDuplicatePartyIDs(t *testing.T) {
	cfg := ThresholdConfig{
		Threshold: 2,
		Parties:   []PartyID{1, 2, 1},
		Self:      1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for duplicate party ids")
	}
}

func TestThresholdConfigRejectsSelfNotInParties(t *testing.T) {
	cfg := ThresholdConfig{
		Threshold: 2,
		Parties:   []PartyID{1, 2},
		Self:      3,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when self not in parties")
	}
}

func TestValidateSignerSetRejectsTooManySigners(t *testing.T) {
	limits := defaultTestThresholdLimits()
	limits.MaxSigners = 3

	keyParties := []PartyID{1, 2, 3, 4, 5}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 2, 3, 4}, limits); err == nil {
		t.Fatal("expected error for too many signers")
	}
}

func TestValidateSignerSetRejectsBelowThreshold(t *testing.T) {
	limits := defaultTestThresholdLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 3, []PartyID{1}, limits); err == nil {
		t.Fatal("expected error for not enough signers")
	}
}

func TestValidateSignerSetRejectsNonParticipant(t *testing.T) {
	limits := defaultTestThresholdLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 4}, limits); err == nil {
		t.Fatal("expected error for non-participant signer")
	}
}

func TestValidateSignerSetRejectsDuplicateSigner(t *testing.T) {
	limits := defaultTestThresholdLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 2, 1}, limits); err == nil {
		t.Fatal("expected error for duplicate signer")
	}
}

func TestValidateSignerSetRejectsEmpty(t *testing.T) {
	limits := defaultTestThresholdLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 2, nil, limits); err == nil {
		t.Fatal("expected error for empty signers")
	}
}

func TestValidateSignerSetOversizedRequiresAllow(t *testing.T) {
	limits := defaultTestThresholdLimits()
	limits.AllowOversizedSignerSet = false
	keyParties := []PartyID{1, 2, 3, 4}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 2, 3}, limits); err == nil {
		t.Fatal("expected error when oversized signer set not allowed")
	}
	// Same with AllowOversizedSignerSet=true should pass.
	limits.AllowOversizedSignerSet = true
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 2, 3}, limits); err != nil {
		t.Fatalf("expected oversized signer set to be allowed: %v", err)
	}
}

func TestDefaultThresholdLimitsIsFailClosed(t *testing.T) {
	l := defaultTestThresholdLimits()
	if l.MinProductionThreshold != 2 {
		t.Errorf("MinProductionThreshold: got %d, want 2", l.MinProductionThreshold)
	}
	if l.AllowOneOfOne {
		t.Error("AllowOneOfOne should be false")
	}
	if l.AllowOversizedSignerSet {
		t.Error("AllowOversizedSignerSet should be false")
	}
}

func TestDefaultThresholdLimitsRejectsBelowMinThreshold(t *testing.T) {
	cfg := ThresholdConfig{
		Threshold: 1,
		Parties:   []PartyID{1, 2},
		Self:      1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for threshold below production minimum")
	}
}
