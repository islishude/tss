package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

// TestFast_RejectsWrongWireTypes verifies that UnmarshalKeyShare and
// UnmarshalPresign reject messages with mismatched wire type identifiers.
// This test does not require any key generation or crypto.
func TestFast_RejectsWrongWireTypes(t *testing.T) {
	t.Parallel()
	wrongKeyShare, err := wire.MarshalFields(tss.Version, "wrong.secp256k1.keyshare", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(wrongKeyShare); err == nil {
		t.Fatal("wrong key share wire type accepted")
	}
	wrongPresign, err := wire.MarshalFields(tss.Version, "wrong.secp256k1.presign", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPresign(wrongPresign); err == nil {
		t.Fatal("wrong presign wire type accepted")
	}
}

// TestFast_Presign_RejectsOverflowThreshold verifies that UnmarshalPresign
// rejects threshold values that overflow int32. It uses a manually constructed
// minimal Presign, so no keygen is required.
func TestFast_Presign_RejectsOverflowThreshold(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, overflow := range []uint32{uint32(1<<31) + 1, ^uint32(0)} {
		mutated, err := testutil.RewriteWireField(raw, presignWireType, presignFieldThreshold, wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalPresign(mutated); err == nil {
			t.Fatalf("presign threshold %d accepted", overflow)
		}
	}
}

// TestFast_KeyShare_RejectsJSONFallback verifies UnmarshalKeyShare rejects
// JSON input instead of silently falling back to a legacy decoder.
func TestFast_KeyShare_RejectsJSONFallback(t *testing.T) {
	t.Parallel()
	if _, err := UnmarshalKeyShare([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON key share encoding accepted")
	}
}

// TestFast_Presign_RejectsJSONFallback verifies UnmarshalPresign rejects JSON.
func TestFast_Presign_RejectsJSONFallback(t *testing.T) {
	t.Parallel()
	if _, err := UnmarshalPresign([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON presign encoding accepted")
	}
}
