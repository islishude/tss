package testutil

import (
	"testing"
)

func TestTestLimits(t *testing.T) {
	tl := TestLimits()
	if tl.MinPaillierModulusBits != 512 {
		t.Errorf("MinPaillierModulusBits: got %d, want 512", tl.MinPaillierModulusBits)
	}
	if !tl.AllowOneOfOne {
		t.Error("AllowOneOfOne should be true")
	}
	if tl.MinProductionThreshold != 1 {
		t.Errorf("MinProductionThreshold: got %d, want 1", tl.MinProductionThreshold)
	}
	if tl.AllowOversizedSignerSet != true {
		t.Error("AllowOversizedSignerSet should be true")
	}
	if tl.MaxParties != 8 || tl.MaxThreshold != 8 || tl.MaxSigners != 8 {
		t.Error("MaxParties/MaxThreshold/MaxSigners should be 8")
	}
}
