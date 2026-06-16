package secp256k1

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

const testResharePlanPaillierBits = 3072

func TestResharePlanValidateAcceptsDealerSubset(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.dealerParties = []tss.PartyID{1, 2}
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
	plan.state.oldGroupPublicKey = mustResharePlanPoint(t, 2)
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted old commitment/public key mismatch")
	}
}

func TestResharePlanValidateRejectsDealerOutsideOldSet(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.dealerParties = []tss.PartyID{4}
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted dealer outside old party set")
	}
}

func TestResharePlanValidateRejectsVerificationShareMismatch(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.oldVerificationShares[2] = mustResharePlanPoint(t, 2)
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
	mutated.state.chainCode = bytes.Repeat([]byte{0x42}, 32)
	digest3, err := mutated.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest1, digest3) {
		t.Fatal("reshare plan digest did not change after chain-code mutation")
	}
}

func TestResharePlanGettersReturnOwnedSnapshots(t *testing.T) {
	t.Parallel()
	plan := minimalValidResharePlan(t)
	plan.state.chainCode = bytes.Repeat([]byte{1}, 32)

	publicKey := plan.OldGroupPublicKeyBytes()
	publicKey[0] ^= 1
	commitments := plan.OldGroupCommitments()
	commitments[0][0] ^= 1
	shares := plan.OldVerificationShares()
	shares[1][0] ^= 1
	delete(shares, 2)
	oldParties := plan.OldParties()
	oldParties[0] = 99
	dealers := plan.DealerParties()
	dealers[0] = 99
	newParties := plan.NewParties()
	newParties[0] = 99
	chainCode := plan.ChainCodeBytes()
	chainCode[0] = 99

	if bytes.Equal(publicKey, plan.state.oldGroupPublicKey) ||
		bytes.Equal(commitments[0], plan.state.oldGroupCommitments[0]) ||
		bytes.Equal(shares[1], plan.state.oldVerificationShares[1]) ||
		len(plan.state.oldVerificationShares) != 3 ||
		plan.state.oldParties[0] != 1 ||
		plan.state.dealerParties[0] != 1 ||
		plan.state.newParties[0] != 2 ||
		plan.state.chainCode[0] != 1 {
		t.Fatal("ResharePlan getter snapshot aliases internal state")
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
	decoded, err := UnmarshalResharePlan(raw1)
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
	if _, err := UnmarshalResharePlan(append(raw1, 0)); err == nil {
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
	if _, err := UnmarshalResharePlan(missing); err == nil {
		t.Fatal("reshare plan accepted missing tag")
	}

	nonCanonical := append([]byte(nil), raw...)
	offsets := resharePlanFieldTagOffsets(t, nonCanonical)
	binary.BigEndian.PutUint16(nonCanonical[offsets[4]:], 6)
	binary.BigEndian.PutUint16(nonCanonical[offsets[5]:], 5)
	if _, err := UnmarshalResharePlan(nonCanonical); err == nil {
		t.Fatal("reshare plan accepted non-canonical tag order")
	}

	duplicate := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(duplicate[offsets[4]:], 6)
	if _, err := UnmarshalResharePlan(duplicate); err == nil {
		t.Fatal("reshare plan accepted duplicate tag")
	}

	reversedShares := wire.EncodePartyBytes([]wire.PartyBytes[tss.PartyID]{
		{Party: 3, Bytes: plan.state.oldVerificationShares[3]},
		{Party: 2, Bytes: plan.state.oldVerificationShares[2]},
		{Party: 1, Bytes: plan.state.oldVerificationShares[1]},
	})
	wrongShareOrder, err := testutil.RewriteWireFieldByName(raw, resharePlanWireType, resharePlanWire{}, "OldVerificationShares", reversedShares)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResharePlan(wrongShareOrder); err == nil {
		t.Fatal("reshare plan accepted verification shares outside old-party order")
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
	if _, err := unmarshalResharePlanWithLimits(raw, limits); err == nil {
		t.Fatal("reshare plan exceeded serialized size limit")
	}
}

func TestGoldenResharePlanMarshalBinary(t *testing.T) {
	t.Parallel()
	raw, err := minimalValidResharePlan(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "cggmp21", "ResharePlan.golden")
	testutil.CheckGolden(t, golden, raw)
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
		sessionID:           sessionID,
		curveID:             reshareCurveID,
		oldGroupPublicKey:   publicKey,
		oldGroupCommitments: [][]byte{publicKey, linearCommitment},
		oldVerificationShares: map[tss.PartyID][]byte{
			1: mustResharePlanPoint(t, 2),
			2: mustResharePlanPoint(t, 3),
			3: mustResharePlanPoint(t, 4),
		},
		oldParties:     []tss.PartyID{1, 2, 3},
		oldThreshold:   2,
		dealerParties:  []tss.PartyID{1, 2},
		newParties:     []tss.PartyID{2, 3},
		newThreshold:   2,
		chainCode:      bytes.Repeat([]byte{0x44}, 32),
		paillierBits:   testResharePlanPaillierBits,
		securityParams: DefaultSecurityParams(),
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
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, nil), NewParties: []tss.PartyID{1}, NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for empty old parties")
	}
}

func TestNewResharePlanRejectsZeroThreshold(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 0, []tss.PartyID{1}), DealerParties: []tss.PartyID{1}, NewParties: []tss.PartyID{2}, NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for zero threshold")
	}
}

func TestNewResharePlanRejectsThresholdExceedsOldParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 3, []tss.PartyID{1, 2}), DealerParties: []tss.PartyID{1}, NewParties: []tss.PartyID{2}, NewThreshold: 2, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error when threshold > old party count")
	}
}

func TestNewResharePlanRejectsThresholdZeroParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, []tss.PartyID{1}), NewParties: []tss.PartyID{1}, NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for empty dealer parties")
	}
}

func TestNewResharePlanRejectsNilNewParties(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, []tss.PartyID{1}), DealerParties: []tss.PartyID{1}, NewThreshold: 1, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error for nil new parties")
	}
}

func TestNewResharePlanRejectsInvalidNewThreshold(t *testing.T) {
	t.Parallel()
	_, err := NewResharePlan(ResharePlanOption{OldKey: testMetadataKeyShare(1, 1, []tss.PartyID{1}), DealerParties: []tss.PartyID{1}, NewParties: []tss.PartyID{2, 3}, NewThreshold: 5, Limits: testLimitsPtr()})
	if err == nil {
		t.Fatal("expected error when newThreshold > new party count")
	}
}

func testMetadataKeyShare(party tss.PartyID, threshold int, parties []tss.PartyID) *KeyShare {
	return &KeyShare{state: &keyShareState{
		version:        tss.Version,
		securityParams: testSecurityParams(),
		party:          party,
		threshold:      threshold,
		parties:        parties,
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
	plan.state.curveID = ""
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate accepted empty CurveID")
	}
}
