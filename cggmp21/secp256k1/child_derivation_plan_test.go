package secp256k1

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/tssrun"
)

func testChildPlanFromXpub(t *testing.T) *ChildDerivationPlan {
	t.Helper()
	parent := mustParseXPub(t, xpubTV2Master)
	path := tss.DerivationPath{0, 1}
	derived, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], path)
	if err != nil {
		t.Fatal(err)
	}
	defer derived.Destroy()
	var parentEpochRaw [32]byte
	parentEpochRaw[0] = 0x41
	parentEpochID, err := tssrun.NewEpochID(parentEpochRaw[:])
	if err != nil {
		t.Fatal(err)
	}
	var parentSID, runSession tss.SessionID
	parentSID[0] = 0x42
	runSession[0] = 0x43
	state := &childDerivationPlanState{
		ParentKeyID:         "parent-key",
		ParentKeyGeneration: "parent-generation-7",
		ParentEpochID:       parentEpochID.Bytes(),
		ParentSID:           parentSID,
		SessionID:           runSession,
		TargetKeyID:         "child-key",
		TargetKeyGeneration: "child-generation-1",
		RequestedPath:       derived.RequestedPath.Clone(),
		ResolvedPath:        derived.ResolvedPath.Clone(),
		InvalidChildMode:    tss.ErrorOnInvalidChild,
		ParentPublicKey:     bytes.Clone(parent.PublicKey),
		ParentChainCode:     bytes.Clone(parent.ChainCode[:]),
		ChildPublicKey:      bytes.Clone(derived.ChildPublicKey),
		ChildChainCode:      bytes.Clone(derived.ChildChainCode),
		Tweak:               bytes.Clone(derived.AdditiveShift),
		Depth:               derived.Depth,
		ParentFingerprint:   bytes.Clone(derived.ParentFingerprint[:]),
		ChildNumber:         derived.ChildNumber,
		Parties:             tss.NewPartySet(1, 2),
		Threshold:           2,
		PaillierBits:        int(testSecurityParams().MinPaillierBits),
		SecurityParams:      testSecurityParams(),
	}
	state.ChildSID, err = deriveChildLineageSID(state)
	if err != nil {
		t.Fatal(err)
	}
	plan := &ChildDerivationPlan{state: state, limits: testLimits()}
	if err := plan.ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("valid child plan: %v", err)
	}
	return plan
}

func cloneChildDerivationPlanForTest(plan *ChildDerivationPlan) *ChildDerivationPlan {
	state := *plan.state
	state.ParentEpochID = bytes.Clone(plan.state.ParentEpochID)
	state.RequestedPath = plan.state.RequestedPath.Clone()
	state.ResolvedPath = plan.state.ResolvedPath.Clone()
	state.ParentPublicKey = bytes.Clone(plan.state.ParentPublicKey)
	state.ParentChainCode = bytes.Clone(plan.state.ParentChainCode)
	state.ChildPublicKey = bytes.Clone(plan.state.ChildPublicKey)
	state.ChildChainCode = bytes.Clone(plan.state.ChildChainCode)
	state.Tweak = bytes.Clone(plan.state.Tweak)
	state.ParentFingerprint = bytes.Clone(plan.state.ParentFingerprint)
	state.Parties = plan.state.Parties.Clone()
	return &ChildDerivationPlan{state: &state, limits: plan.limits}
}

func TestChildDerivationPlanWireRoundTripAndSnapshotIsolation(t *testing.T) {
	plan := testChildPlanFromXpub(t)
	raw1, err := plan.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := plan.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("child plan encoding is not deterministic")
	}
	var decoded ChildDerivationPlan
	if err := decoded.UnmarshalBinaryWithLimits(raw1, testLimits()); err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, reencoded) {
		t.Fatal("child plan did not round-trip canonically")
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
		t.Fatal("child plan digest changed after wire round trip")
	}
	snapshot, ok := decoded.Snapshot()
	if !ok {
		t.Fatal("missing child plan snapshot")
	}
	snapshot.Derivation.AdditiveShift[0] ^= 0xff
	snapshot.Parties[0] = 99
	again, ok := decoded.Snapshot()
	if !ok || bytes.Equal(snapshot.Derivation.AdditiveShift, again.Derivation.AdditiveShift) || again.Parties[0] != 1 {
		t.Fatal("child plan snapshot leaked mutable state")
	}
}

func TestChildDerivationPlanRejectsBoundFieldSubstitution(t *testing.T) {
	base := testChildPlanFromXpub(t)
	tests := []struct {
		name   string
		mutate func(*childDerivationPlanState)
	}{
		{name: "empty path", mutate: func(s *childDerivationPlanState) { s.RequestedPath = nil }},
		{name: "hardened path", mutate: func(s *childDerivationPlanState) { s.RequestedPath[0] = tss.HardenedKeyStart }},
		{name: "resolved path", mutate: func(s *childDerivationPlanState) { s.ResolvedPath[0]++ }},
		{name: "parent epoch", mutate: func(s *childDerivationPlanState) { s.ParentEpochID[0] ^= 1 }},
		{name: "target reuses parent", mutate: func(s *childDerivationPlanState) { s.TargetKeyID = s.ParentKeyID }},
		{name: "target generation", mutate: func(s *childDerivationPlanState) { s.TargetKeyGeneration = "" }},
		{name: "child public key", mutate: func(s *childDerivationPlanState) { s.ChildPublicKey[5] ^= 1 }},
		{name: "child chain code", mutate: func(s *childDerivationPlanState) { s.ChildChainCode[0] ^= 1 }},
		{name: "tweak", mutate: func(s *childDerivationPlanState) { s.Tweak[0] ^= 1 }},
		{name: "parties", mutate: func(s *childDerivationPlanState) { s.Parties = tss.NewPartySet(1, 3) }},
		{name: "threshold", mutate: func(s *childDerivationPlanState) { s.Threshold = 1 }},
		{name: "security profile", mutate: func(s *childDerivationPlanState) { s.SecurityParams.Ell++ }},
		{name: "child sid", mutate: func(s *childDerivationPlanState) { s.ChildSID[0] ^= 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneChildDerivationPlanForTest(base)
			tc.mutate(mutated.state)
			if err := mutated.ValidateWithLimits(testLimits()); err == nil {
				t.Fatal("mutated child plan was accepted")
			}
		})
	}
}

func TestChildDerivationPlanOpaqueSurfaceHasNoExportedState(t *testing.T) {
	typ := reflect.TypeFor[ChildDerivationPlan]()
	for field := range typ.Fields() {
		if field.IsExported() {
			t.Fatalf("ChildDerivationPlan exposes field %q", field.Name)
		}
	}
}

func TestChildFigure7ContributionAddsTweakExactlyOnce(t *testing.T) {
	parties := tss.NewPartySet(1, 2, 3)
	var sid, rid tss.SessionID
	sid[0] = 0x61
	rid[0] = 0x62
	constant := secp.ScalarFromUint64(17)
	slope := secp.ScalarFromUint64(9)
	publicShares := make([]EpochPublicShare, len(parties))
	secretShares := make(map[tss.PartyID]secp.Scalar, len(parties))
	for i, party := range parties {
		identifierBytes, err := DeriveEpochIdentifier(sid, rid, party)
		if err != nil {
			t.Fatal(err)
		}
		x, err := shamir.IdentifierFromBytes(identifierBytes)
		if err != nil {
			t.Fatal(err)
		}
		share, err := shamir.EvalAt(shamir.Polynomial{constant, slope}, x)
		if err != nil {
			t.Fatal(err)
		}
		secretShares[party] = share
		point, err := secp.PointBytes(secp.ScalarBaseMult(share))
		if err != nil {
			t.Fatal(err)
		}
		publicShares[i] = EpochPublicShare{Party: party, PublicKey: point}
	}
	auxDigest := bytes.Repeat([]byte{0x33}, 32)
	epoch, err := NewEpochContext(EpochContextOption{
		SID: sid, RID: rid, Threshold: 2, Parties: parties,
		PublicShares: publicShares, AuxiliaryDigest: auxDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	localSecret, err := secpSecretScalarFromScalar(secretShares[1])
	if err != nil {
		t.Fatal(err)
	}
	defer localSecret.Destroy()
	tweak := secp.ScalarFromUint64(5)
	childPublic, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarAdd(constant, tweak)))
	if err != nil {
		t.Fatal(err)
	}
	plan := &ChildDerivationPlan{state: &childDerivationPlanState{Tweak: tweak.Bytes(), ChildPublicKey: childPublic}}
	parent := &KeyShare{state: &keyShareState{Party: 1, Parties: parties, Secret: localSecret, Epoch: epoch}}
	contribution, expected, err := childFigure7Contributions(parent, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer contribution.Destroy()
	defer clearPublicPointMap(expected)
	lambda, err := epochLagrangeCoefficient(epoch, 1, parties)
	if err != nil {
		t.Fatal(err)
	}
	want := secp.ScalarMul(lambda, secp.ScalarAdd(secretShares[1], tweak))
	got, err := secpScalarFromSecret(contribution)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatal("local child contribution did not use the dynamic parent coefficient")
	}
	aggregate := secp.NewInfinity()
	for _, party := range parties {
		point, err := secp.PointFromBytes(expected[party])
		if err != nil {
			t.Fatal(err)
		}
		aggregate = secp.Add(aggregate, point)
	}
	aggregateBytes, err := secp.PointBytes(aggregate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aggregateBytes, childPublic) {
		t.Fatal("aggregate contributions did not add exactly one tweak")
	}
	wrong, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarAdd(constant, secp.ScalarMul(secp.ScalarFromUint64(uint64(len(parties))), tweak))))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(aggregateBytes, wrong) {
		t.Fatal("aggregate contributions added one tweak per party")
	}
}

func TestChildDerivationPlanWireRejectsTrailingDataAndSizeLimit(t *testing.T) {
	plan := testChildPlanFromXpub(t)
	raw, err := plan.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	var decoded ChildDerivationPlan
	if err := decoded.UnmarshalBinaryWithLimits(append(bytes.Clone(raw), 0), testLimits()); err == nil {
		t.Fatal("child plan accepted trailing data")
	}
	limits := testLimits()
	limits.State.MaxSerializedChildDerivationPlanBytes = len(raw) - 1
	if err := decoded.UnmarshalBinaryWithLimits(raw, limits); err == nil {
		t.Fatal("child plan accepted an oversized record")
	}
}

func TestChildTargetDescriptorValidationRejectsMissingGeneration(t *testing.T) {
	var raw [32]byte
	raw[0] = 1
	epoch, err := tssrun.NewEpochID(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateChildTargetDescriptor("child", "", epoch); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("target validation error = %v", err)
	}
}
