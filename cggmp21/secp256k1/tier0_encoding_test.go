package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func FuzzCGGMPPresignCanonicalDecode(f *testing.F) {
	presign := minimalCGGMP21Presign(f)
	seed, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		presign.Destroy()
		f.Fatal(err)
	}
	presign.Destroy()
	f.Add(seed)
	f.Fuzz(func(t *testing.T, in []byte) {
		var decoded Presign
		if err := decoded.UnmarshalBinaryWithLimits(in, testLimits()); err != nil {
			return
		}
		defer decoded.Destroy()
		canonical, err := decoded.MarshalBinaryWithLimits(testLimits())
		if err != nil {
			t.Fatalf("accepted presign failed canonical re-encode: %v", err)
		}
		defer clear(canonical)
		if !bytes.Equal(canonical, in) {
			t.Fatal("presign decoder accepted a non-canonical wire representation")
		}
	})
}

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
	smallFields["signers"] = 1
	if _, err := wire.Marshal(presign.state, wire.WithFieldLimitsForMarshal(smallFields)); err == nil {
		t.Fatal("presign state marshal ignored caller field limits")
	}
	var decoded presignState
	if err := wire.Unmarshal(
		raw,
		&decoded,
		wire.WithFrameLimits(limits.frameLimits(len(raw)-1)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err == nil {
		t.Fatal("presign state unmarshal ignored caller frame limits")
	}
	if err := wire.Unmarshal(
		raw,
		&decoded,
		wire.WithFrameLimits(limits.frameLimits(len(raw))),
		wire.WithFieldLimits(smallFields),
	); err == nil {
		t.Fatal("presign state unmarshal ignored caller field limits")
	}
	missing := limits.fieldLimits()
	delete(missing, "point")
	if _, err := wire.Marshal(presign.state, wire.WithFieldLimitsForMarshal(missing)); err == nil {
		t.Fatal("presign state marshal accepted missing field limit")
	}
}

func TestFast_PresignCodecReceivesCompleteLimits(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	presign.state.Threshold = 1
	presign.state.Signers = tss.NewPartySet(1)
	presign.state.Commitments = presign.state.Commitments[:1]
	presign.state.PartiesHash = tss.PartySetHash(presign.state.Signers, partySetHashLabel)
	publicKey, err := secp.PointBytes(presign.state.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	presign.state.Epoch, err = NewEpochContext(EpochContextOption{
		SID:             presign.state.Epoch.SID,
		RID:             presign.state.Epoch.RID,
		Threshold:       1,
		Parties:         presign.state.Signers,
		PublicShares:    []EpochPublicShare{{Party: 1, PublicKey: publicKey}},
		AuxiliaryDigest: presign.state.Epoch.AuxiliaryDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	presign.state.EpochID = append([]byte(nil), presign.state.Epoch.EpochID...)

	raw, err := presign.marshalWireMessageWithLimits(testLimits())
	if err != nil {
		t.Fatalf("limits-aware codec rejected 1-of-1 presign: %v", err)
	}
	var decoded Presign
	if err := decoded.unmarshalWireMessageWithLimits(raw, testLimits()); err != nil {
		t.Fatalf("limits-aware codec failed 1-of-1 round trip: %v", err)
	}
	if _, err := presign.MarshalWireMessage(
		wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
	); err == nil {
		t.Fatal("wire.Message adapter inferred non-production threshold policy from FieldLimits")
	}
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFieldLimits(testLimits().fieldLimits()),
	); err == nil {
		t.Fatal("wire.Message adapter inferred non-production decode policy from FieldLimits")
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
	fields[len(fields)-1].Tag = 23
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
