package secp256k1

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/testvectors"
	"github.com/islishude/tss/internal/wire"
)

const testResharePlanPaillierBits = 3072

func TestResharePlanValidateAcceptsDealerSubset(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.DealerParties = tss.NewPartySet(1, 2)
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !plan.IsDealer(2) {
		t.Fatal("party 2 should be a dealer")
	}
	if !plan.IsReceiver(3) {
		t.Fatal("party 3 should be a receiver")
	}
	if plan.IsOverlap(1) {
		t.Fatal("party 1 should not overlap")
	}
}

func TestResharePlanValidateRejectsWrongOldPublicKey(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.OldGroupPublicKey = mustResharePlanPoint(t, 2)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted old commitment/public key mismatch")
	}
}

func TestResharePlanValidateRejectsDealerOutsideOldSet(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.DealerParties = tss.NewPartySet(4)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted dealer outside old party set")
	}
}

func TestResharePlanValidateRejectsVerificationShareMismatch(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.OldVerificationShares[2] = mustResharePlanPoint(t, 2)
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
	mutated := cloneResharePlan(plan)
	mutated.state.ChainCode = bytes.Repeat([]byte{0x42}, 32)
	digest3, err := mutated.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest1, digest3) {
		t.Fatal("reshare plan digest did not change after chain-code mutation")
	}
}

func TestResharePlanSnapshotReturnsOwnedValues(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.ChainCode = bytes.Repeat([]byte{1}, 32)

	snapshot, ok := plan.Snapshot()
	if !ok {
		t.Fatal("missing reshare plan snapshot")
	}
	snapshot.OldGroupPublicKey[0] ^= 1
	snapshot.OldGroupCommitments[0][0] ^= 1
	oldShare, ok := plan.OldVerificationShare(1)
	if !ok {
		t.Fatal("missing old verification share")
	}
	oldShare.PublicKey[0] ^= 1
	snapshot.OldParties[0] = 99
	snapshot.DealerParties[0] = 99
	snapshot.NewParties[0] = 99
	snapshot.ChainCode[0] = 99

	if bytes.Equal(snapshot.OldGroupPublicKey, plan.state.OldGroupPublicKey) ||
		bytes.Equal(snapshot.OldGroupCommitments[0], plan.state.OldGroupCommitments[0]) ||
		bytes.Equal(oldShare.PublicKey, plan.state.OldVerificationShares[1]) ||
		len(plan.state.OldVerificationShares) != 3 ||
		plan.state.OldParties[0] != 1 ||
		plan.state.DealerParties[0] != 1 ||
		plan.state.NewParties[0] != 2 ||
		plan.state.ChainCode[0] != 1 {
		t.Fatal("ResharePlan snapshot aliases internal state")
	}
}

func TestResharePlanCanonicalEncoding(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	raw1, err := plan.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := plan.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("reshare plan encoding is not deterministic")
	}
	decoded, err := tss.DecodeBinary[ResharePlan](raw1)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := decoded.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantDigest, gotDigest) {
		t.Fatal("reshare plan digest changed after round trip")
	}
	raw3, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw3) {
		t.Fatal("reshare plan wire bytes changed after round trip")
	}
	if _, err := tss.DecodeBinary[ResharePlan](append(raw1, 0)); err == nil {
		t.Fatal("reshare plan accepted trailing data")
	}
}

func TestResharePlanRejectsNonCanonicalEncoding(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	raw, err := plan.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	version, fields, err := wire.UnmarshalFields(raw, resharePlanWireType)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := wire.MarshalFields(version, resharePlanWireType, fields[:len(fields)-1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[ResharePlan](missing); err == nil {
		t.Fatal("reshare plan accepted missing tag")
	}

	nonCanonical := append([]byte(nil), raw...)
	offsets := resharePlanFieldTagOffsets(t, nonCanonical)
	binary.BigEndian.PutUint16(nonCanonical[offsets[4]:], 6)
	binary.BigEndian.PutUint16(nonCanonical[offsets[5]:], 5)
	if _, err := tss.DecodeBinary[ResharePlan](nonCanonical); err == nil {
		t.Fatal("reshare plan accepted non-canonical tag order")
	}

	duplicate := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(duplicate[offsets[4]:], 6)
	if _, err := tss.DecodeBinary[ResharePlan](duplicate); err == nil {
		t.Fatal("reshare plan accepted duplicate tag")
	}

	reversedShares := wire.EncodePartyBytes([]wire.PartyBytes[tss.PartyID]{
		{Party: 3, Bytes: plan.state.OldVerificationShares[3]},
		{Party: 2, Bytes: plan.state.OldVerificationShares[2]},
		{Party: 1, Bytes: plan.state.OldVerificationShares[1]},
	})
	wrongShareOrder, err := testutil.RewriteWireField(raw, resharePlanWireType, 5, reversedShares)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[ResharePlan](wrongShareOrder); err == nil {
		t.Fatal("reshare plan accepted verification shares outside old-party order")
	}
}

func TestResharePlanCodecAppliesCallerLimits(t *testing.T) {
	t.Parallel()

	plan := minimalValidResharePlan(t)
	limits := testLimits()
	raw, err := plan.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	smallFields := limits.fieldLimits()
	smallFields["point"] = len(plan.state.OldGroupPublicKey) - 1
	if _, err := plan.MarshalWireMessage(wire.WithFieldLimitsForMarshal(smallFields)); err == nil {
		t.Fatal("reshare plan marshal ignored caller field limits")
	}
	var decoded ResharePlan
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw)-1)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err == nil {
		t.Fatal("reshare plan unmarshal ignored caller frame limits")
	}
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw))),
		wire.WithFieldLimits(smallFields),
	); err == nil {
		t.Fatal("reshare plan unmarshal ignored caller field limits")
	}
	missing := limits.fieldLimits()
	delete(missing, "point")
	if _, err := plan.MarshalWireMessage(wire.WithFieldLimitsForMarshal(missing)); err == nil {
		t.Fatal("reshare plan marshal accepted missing field limit")
	}
}

func TestResharePlanSerializedSizeLimit(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	raw, err := plan.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	limits := testLimits()
	limits.State.MaxSerializedResharePlanBytes = len(raw) - 1
	if _, err := tss.DecodeBinaryWithLimits[ResharePlan](raw, limits); err == nil {
		t.Fatal("reshare plan exceeded serialized size limit")
	}
}

func TestGoldenResharePlanMarshalBinary(t *testing.T) {
	t.Parallel()
	raw, err := minimalValidResharePlan(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/ResharePlan.golden", raw)
}

func TestNilResharePlanMarshalBinary(t *testing.T) {
	t.Parallel()

	var plan *ResharePlan
	if _, err := plan.MarshalBinary(); err == nil {
		t.Fatal("nil ResharePlan marshaled successfully")
	}
}

func resharePlanFieldTagOffsets(t *testing.T, raw []byte) []int {
	t.Helper()
	if len(raw) < 8 {
		t.Fatal("short reshare plan wire input")
	}
	typeLen := int(binary.BigEndian.Uint16(raw[4:6]))
	offset := 4 + 2 + typeLen + 2
	count := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	out := make([]int, 0, count)
	for range count {
		if len(raw)-offset < 6 {
			t.Fatal("truncated reshare plan wire field")
		}
		out = append(out, offset)
		length := int(binary.BigEndian.Uint32(raw[offset+2 : offset+6]))
		offset += 6 + length
	}
	if offset != len(raw) {
		t.Fatal("unexpected trailing bytes in canonical reshare plan")
	}
	return out
}

func minimalValidResharePlan(t *testing.T) *ResharePlan {
	t.Helper()
	var sessionID tss.SessionID
	sessionID[0] = 1
	publicKey := mustResharePlanPoint(t, 1)
	linearCommitment := mustResharePlanPoint(t, 1)
	return &ResharePlan{state: &resharePlanState{
		SessionID:           sessionID,
		CurveID:             reshareCurveID,
		OldGroupPublicKey:   publicKey,
		OldGroupCommitments: [][]byte{publicKey, linearCommitment},
		OldVerificationShares: map[tss.PartyID][]byte{
			1: mustResharePlanPoint(t, 2),
			2: mustResharePlanPoint(t, 3),
			3: mustResharePlanPoint(t, 4),
		},
		OldParties:     tss.NewPartySet(1, 2, 3),
		OldThreshold:   2,
		DealerParties:  tss.NewPartySet(1, 2),
		NewParties:     tss.NewPartySet(2, 3),
		NewThreshold:   2,
		ChainCode:      bytes.Repeat([]byte{0x44}, 32),
		PaillierBits:   testResharePlanPaillierBits,
		SecurityParams: DefaultSecurityParams(),
	}, limits: DefaultLimits()}
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
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, nil), NewParties: tss.NewPartySet(1), NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for empty old parties")
	}
}

func TestNewResharePlanRejectsZeroThreshold(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 0, tss.NewPartySet(1)), DealerParties: tss.NewPartySet(1), NewParties: tss.NewPartySet(2), NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for zero threshold")
	}
}

func TestNewResharePlanRejectsThresholdExceedsOldParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 3, tss.NewPartySet(1, 2)), DealerParties: tss.NewPartySet(1), NewParties: tss.NewPartySet(2), NewThreshold: 2, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error when threshold > old party count")
	}
}

func TestNewResharePlanRejectsThresholdZeroParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, tss.NewPartySet(1)), NewParties: tss.NewPartySet(1), NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for empty dealer parties")
	}
}

func TestNewResharePlanRejectsNilNewParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, tss.NewPartySet(1)), DealerParties: tss.NewPartySet(1), NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for nil new parties")
	}
}

func TestNewResharePlanRejectsInvalidNewThreshold(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, tss.NewPartySet(1)), DealerParties: tss.NewPartySet(1), NewParties: tss.NewPartySet(2, 3), NewThreshold: 5, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error when newThreshold > new party count")
	}
}

func testMetadataKeyShare(party tss.PartyID, threshold int, parties tss.PartySet) *KeyShare {
	return &KeyShare{state: &keyShareState{
		SecurityParams: testSecurityParams(),
		Party:          party,
		Threshold:      threshold,
		Parties:        parties,
	}}
}

func TestIsDealerReceiverOverlapFalseForNonMembers(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	if plan.IsDealer(99) {
		t.Fatal("party 99 should not be a dealer")
	}
	if plan.IsReceiver(99) {
		t.Fatal("party 99 should not be a receiver")
	}
	if plan.IsOverlap(99) {
		t.Fatal("party 99 should not be overlap")
	}
}

func TestResharePlanValidateRejectsNilCurveID(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.CurveID = ""
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted empty CurveID")
	}
}
