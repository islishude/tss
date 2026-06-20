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
	wrongKeyShare, err := wire.MarshalFields(keyShareWireVersion, "wrong.secp256k1.keyshare", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[KeyShare](wrongKeyShare); err == nil {
		t.Fatal("wrong key share wire type accepted")
	}
	wrongPresign, err := wire.MarshalFields(presignWireVersion, "wrong.secp256k1.presign", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[Presign](wrongPresign); err == nil {
		t.Fatal("wrong presign wire type accepted")
	}
	wrongAttempt, err := wire.MarshalFields(signAttemptWireVersion, "wrong.secp256k1.sign-attempt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValue[SignAttemptRecord](wrongAttempt); err == nil {
		t.Fatal("wrong sign attempt wire type accepted")
	}
}

// TestFast_Presign_RejectsOverflowThreshold verifies that UnmarshalPresign
// rejects threshold values that overflow int32. It uses a manually constructed
// minimal Presign, so no keygen is required.
func TestFast_Presign_RejectsOverflowThreshold(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, overflow := range []uint32{uint32(1<<31) + 1, ^uint32(0)} {
		mutated, err := testutil.RewriteWireField(raw, presignWireType, 2, wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tss.DecodeBinary[Presign](mutated); err == nil {
			t.Fatalf("presign threshold %d accepted", overflow)
		}
	}
}

func TestFast_PresignStateCodecAppliesCallerLimits(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	limits := testLimits()
	raw, err := presign.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	smallFields := limits.fieldLimits()
	smallFields["point"] = 32
	if _, err := presign.state.MarshalWireMessage(wire.WithFieldLimitsForMarshal(smallFields)); err == nil {
		t.Fatal("presign state marshal ignored caller field limits")
	}
	var decoded presignState
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw)-1)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err == nil {
		t.Fatal("presign state unmarshal ignored caller frame limits")
	}
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw))),
		wire.WithFieldLimits(smallFields),
	); err == nil {
		t.Fatal("presign state unmarshal ignored caller field limits")
	}
	missing := limits.fieldLimits()
	delete(missing, "signprep_proof")
	if _, err := presign.state.MarshalWireMessage(wire.WithFieldLimitsForMarshal(missing)); err == nil {
		t.Fatal("presign state marshal accepted missing field limit")
	}
}

func TestFast_PresignStateRejectsNonCanonicalFieldSet(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := wire.UnmarshalFields(raw, presignWireType)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := wire.MarshalFields(version, presignWireType, fields[:len(fields)-1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryWithLimits[Presign](missing, testLimits()); err == nil {
		t.Fatal("presign state accepted missing field")
	}
	fields[len(fields)-1].Tag = 20
	unknown, err := wire.MarshalFields(version, presignWireType, fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryWithLimits[Presign](unknown, testLimits()); err == nil {
		t.Fatal("presign state accepted unknown field")
	}
}

// TestFast_KeyShare_RejectsJSONFallback verifies UnmarshalKeyShare rejects
// JSON input instead of silently falling back to a legacy decoder.
func TestFast_KeyShare_RejectsJSONFallback(t *testing.T) {
	t.Parallel()
	if _, err := tss.DecodeBinary[KeyShare]([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON key share encoding accepted")
	}
}

// TestFast_Presign_RejectsJSONFallback verifies UnmarshalPresign rejects JSON.
func TestFast_Presign_RejectsJSONFallback(t *testing.T) {
	t.Parallel()
	if _, err := tss.DecodeBinary[Presign]([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON presign encoding accepted")
	}
}

// TestFast_SignAttempt_RejectsJSONFallback verifies sign-attempt decoding does
// not accept JSON.
func TestFast_SignAttempt_RejectsJSONFallback(t *testing.T) {
	t.Parallel()
	if _, err := tss.DecodeBinaryValue[SignAttemptRecord]([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON sign attempt encoding accepted")
	}
}
