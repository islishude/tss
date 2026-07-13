package secp256k1

import (
	"bytes"
	"math/bits"
	"sort"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
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

func TestCGGMP21ArtifactsPersistSecurityParams(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	limits := testLimits()
	want := testSecurityParams()

	key := shares[1]
	if err := key.Validate(); err == nil {
		t.Fatal("production Validate accepted a test-profile key share")
	}
	if err := key.ValidateWithLimits(limits); err != nil {
		t.Fatalf("ValidateWithLimits rejected a test-profile key share: %v", err)
	}
	keyRaw, err := key.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	restoredKey, err := tss.DecodeBinaryWithLimits[KeyShare](keyRaw, limits)
	if err != nil {
		t.Fatal(err)
	}
	if restoredKey.SecurityParams() != want {
		t.Fatalf("key security params = %+v, want %+v", restoredKey.SecurityParams(), want)
	}

	presigns := secpPresignWithContext(t, shares, tss.NewPartySet(1, 2), testPresignContext())
	presign := presigns[1]
	if err := presign.Validate(); err == nil {
		t.Fatal("production Validate accepted a test-profile presign")
	}
	if err := presign.ValidateWithLimits(limits); err != nil {
		t.Fatalf("ValidateWithLimits rejected a test-profile presign: %v", err)
	}
	presignRaw, err := presign.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	restoredPresign, err := tss.DecodeBinaryWithLimits[Presign](presignRaw, limits)
	if err != nil {
		t.Fatal(err)
	}
	if restoredPresign.SecurityParams() != want {
		t.Fatalf("presign security params = %+v, want %+v", restoredPresign.SecurityParams(), want)
	}
	presignContentID, err := presign.contentID()
	if err != nil {
		t.Fatal(err)
	}
	restoredContentID, err := restoredPresign.contentID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(presignContentID, restoredContentID) {
		t.Fatal("presign content ID changed after security-profile round trip")
	}
}

func TestCGGMP21TrustedDealerDefaultValidationRejectsTestProfile(t *testing.T) {
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

func TestCGGMP21RejectsSecurityParamsMismatch(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	limits := testLimits()
	production := DefaultSecurityParams()
	sessionID := cggmpPlanTestSession(0x63)

	if _, err := NewPresignPlan(PresignPlanOption{
		Key:            shares[1],
		SessionID:      sessionID,
		PresignID:      sessionID[:],
		Signers:        tss.NewPartySet(1, 2),
		Context:        testPresignContext(),
		Limits:         &limits,
		SecurityParams: &production,
	}); err == nil {
		t.Fatal("presign plan accepted security params that differ from the key")
	}

	presigns := secpPresignWithContext(t, shares, tss.NewPartySet(1, 2), testPresignContext())
	mismatched := clonePresignForTest(presigns[1])
	mismatched.state.SecurityParams = production
	if err := validatePresign(shares[1], mismatched, limits); err == nil {
		t.Fatal("presign validation accepted mismatched key and presign security params")
	} else if err.Error() != "presign security params mismatch" {
		t.Fatalf("presign validation error = %q, want security params mismatch", err)
	}
	if _, err := NewSignPlan(SignPlanOption{
		Key:     shares[1],
		Presign: mustPresignMetadata(t, mismatched),
		Intent: SignIntent{
			SessionID: sessionID,
			Context:   testPresignContext(),
			Message:   []byte("security profile mismatch"),
			Signers:   mismatched.state.Signers,
		},
		Limits: &limits,
	}); err == nil {
		t.Fatal("sign plan accepted mismatched key and presign security params")
	}
}

func TestCGGMP21ArtifactsRejectFlattenedSecurityParamsWire(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	limits := testLimits()

	keyRaw, err := shares[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	keyRaw = flattenSecurityParamsRecordForTest(t, keyRaw, keyShareWireType, 16, shares[1].state.SecurityParams)
	if _, err := tss.DecodeBinaryWithLimits[KeyShare](keyRaw, limits); err == nil {
		t.Fatal("key share accepted retired flattened security params")
	}

	presigns := secpPresignWithContext(t, shares, tss.NewPartySet(1, 2), testPresignContext())
	presignRaw, err := presigns[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	presignRaw = flattenSecurityParamsRecordForTest(t, presignRaw, presignWireType, 18, presigns[1].state.SecurityParams)
	if _, err := tss.DecodeBinaryWithLimits[Presign](presignRaw, limits); err == nil {
		t.Fatal("presign accepted retired flattened security params")
	}

	resharePlan := minimalValidResharePlan(t)
	reshareRaw, err := resharePlan.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reshareRaw = flattenSecurityParamsRecordForTest(t, reshareRaw, resharePlanWireType, 13, resharePlan.state.SecurityParams)
	if _, err := tss.DecodeBinaryWithLimits[ResharePlan](reshareRaw, resharePlan.limits); err == nil {
		t.Fatal("reshare plan accepted retired flattened security params")
	}
}

func flattenSecurityParamsRecordForTest(t *testing.T, raw []byte, wireType string, recordTag uint16, params SecurityParams) []byte {
	t.Helper()

	version, fields, err := wire.UnmarshalFields(raw, wireType)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]wire.Field, 0, len(fields)+4)
	for _, field := range fields {
		if field.Tag < recordTag || field.Tag > recordTag+4 {
			out = append(out, field)
		}
	}
	out = append(out,
		wire.Field{Tag: recordTag, Value: wire.Uint32(params.Ell)},
		wire.Field{Tag: recordTag + 1, Value: wire.Uint32(params.EllPrime)},
		wire.Field{Tag: recordTag + 2, Value: wire.Uint32(params.Epsilon)},
		wire.Field{Tag: recordTag + 3, Value: wire.Uint32(params.ChallengeBits)},
		wire.Field{Tag: recordTag + 4, Value: wire.Uint32(params.MinPaillierBits)},
	)
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	raw, err = wire.MarshalFields(version, wireType, out)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
