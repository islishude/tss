package tss

import (
	"testing"
)

func TestThresholdConfigRejectsTooManyParties(t *testing.T) {
	limits := DefaultLimits()
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
	limits := DefaultLimits()
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
	// DefaultLimits allows 1-of-1 (backward-compat).
	cfg := ThresholdConfig{
		Threshold: 1,
		Parties:   []PartyID{1},
		Self:      1,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultLimits should allow 1-of-1: %v", err)
	}

	// Explicit block: AllowOneOfOne=false, MinProductionThreshold=2
	limits := DefaultLimits()
	limits.AllowOneOfOne = false
	limits.MinProductionThreshold = 2
	if err := cfg.ValidateWithLimits(limits); err == nil {
		t.Fatal("expected error for 1-of-1 when blocked")
	}

	// Explicit allow with AllowOneOfOne=true
	limits.AllowOneOfOne = true
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
		Threshold: 1,
		Parties:   []PartyID{1, 2},
		Self:      3,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when self not in parties")
	}
}

func TestValidateSignerSetRejectsTooManySigners(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxSigners = 3

	keyParties := []PartyID{1, 2, 3, 4, 5}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 2, 3, 4}, limits); err == nil {
		t.Fatal("expected error for too many signers")
	}
}

func TestValidateSignerSetRejectsBelowThreshold(t *testing.T) {
	limits := DefaultLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 3, []PartyID{1}, limits); err == nil {
		t.Fatal("expected error for not enough signers")
	}
}

func TestValidateSignerSetRejectsNonParticipant(t *testing.T) {
	limits := DefaultLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 4}, limits); err == nil {
		t.Fatal("expected error for non-participant signer")
	}
}

func TestValidateSignerSetRejectsDuplicateSigner(t *testing.T) {
	limits := DefaultLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 2, []PartyID{1, 2, 1}, limits); err == nil {
		t.Fatal("expected error for duplicate signer")
	}
}

func TestValidateSignerSetRejectsEmpty(t *testing.T) {
	limits := DefaultLimits()
	keyParties := []PartyID{1, 2, 3}
	if err := ValidateSignerSet(keyParties, 2, nil, limits); err == nil {
		t.Fatal("expected error for empty signers")
	}
}

func TestValidateSignerSetOversizedRequiresAllow(t *testing.T) {
	limits := DefaultLimits()
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

func TestLimitsValidateSelfConsistency(t *testing.T) {
	// Valid limits.
	l := DefaultLimits()
	if err := l.Validate(); err != nil {
		t.Fatalf("DefaultLimits should be valid: %v", err)
	}

	// MaxThreshold > MaxParties.
	l.MaxParties = 5
	l.MaxThreshold = 10
	if err := l.Validate(); err == nil {
		t.Fatal("expected error when MaxThreshold > MaxParties")
	}

	// MinPaillierModulusBits > MaxPaillierModulusBits.
	l = DefaultLimits()
	l.MinPaillierModulusBits = 8192
	l.MaxPaillierModulusBits = 4096
	if err := l.Validate(); err == nil {
		t.Fatal("expected error when Min > Max Paillier bits")
	}
}

func TestDefaultLimitsForAlgorithm(t *testing.T) {
	frost := DefaultLimitsForAlgorithm(AlgorithmFROSTEd25519)
	if frost.MaxParties != MaxFROSTParties {
		t.Errorf("FROST MaxParties: got %d, want %d", frost.MaxParties, MaxFROSTParties)
	}
	if frost.MaxThreshold != MaxFROSTThreshold {
		t.Errorf("FROST MaxThreshold: got %d, want %d", frost.MaxThreshold, MaxFROSTThreshold)
	}

	cggmp := DefaultLimitsForAlgorithm(AlgorithmCGGMP21Secp256k1)
	if cggmp.MaxParties != MaxCGGMPParties {
		t.Errorf("CGGMP MaxParties: got %d, want %d", cggmp.MaxParties, MaxCGGMPParties)
	}
	if cggmp.MaxThreshold != MaxCGGMPThreshold {
		t.Errorf("CGGMP MaxThreshold: got %d, want %d", cggmp.MaxThreshold, MaxCGGMPThreshold)
	}
}

func TestTestLimitsAllowsSmallPaillier(t *testing.T) {
	tl := TestLimits()
	if tl.MinPaillierModulusBits != 512 {
		t.Errorf("TestLimits MinPaillierModulusBits: got %d, want 512", tl.MinPaillierModulusBits)
	}
	if !tl.AllowOneOfOne {
		t.Error("TestLimits should allow 1-of-1")
	}
}
