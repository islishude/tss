package ed25519

import (
	"bytes"
	"strings"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

type oldGroupCommitmentsWire struct {
	Threshold        int      `wire:"1,u32"`
	GroupCommitments [][]byte `wire:"2,byteslist,max_bytes=point,max_items=threshold"`
}

func (oldGroupCommitmentsWire) WireType() string { return "test.frost.group-commitments" }

func (oldGroupCommitmentsWire) WireVersion() uint16 { return 1 }

type newGroupCommitmentsWire struct {
	Threshold        int              `wire:"1,u32"`
	GroupCommitments groupCommitments `wire:"2,custom,max_items=threshold"`
}

func (newGroupCommitmentsWire) WireType() string { return "test.frost.group-commitments" }

func (newGroupCommitmentsWire) WireVersion() uint16 { return 1 }

type oldKeygenCommitmentsPayloadWire struct {
	Commitments     [][]byte `wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	ChainCodeCommit []byte   `wire:"2,bytes"`
	PlanHash        []byte   `wire:"3,bytes,len=32"`
}

func (oldKeygenCommitmentsPayloadWire) WireType() string { return keygenCommitmentsPayloadWireType }

func (oldKeygenCommitmentsPayloadWire) WireVersion() uint16 {
	return keygenCommitmentsPayloadWireVersion
}

type oldReshareCommitmentsPayloadWire struct {
	Commitments [][]byte `wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PlanHash    []byte   `wire:"2,bytes,len=32"`
}

func (oldReshareCommitmentsPayloadWire) WireType() string { return reshareCommitmentsPayloadWireType }

func (oldReshareCommitmentsPayloadWire) WireVersion() uint16 {
	return reshareCommitmentsPayloadWireVersion
}

func TestSemanticCommitmentIdentityPolicies(t *testing.T) {
	t.Parallel()
	generator := fed.NewGeneratorPoint()
	identity := fed.NewIdentityPoint()

	if _, err := newKeygenCommitmentsFromPoints([]*fed.Point{identity, generator}, 2); err == nil {
		t.Fatal("keygen commitments accepted identity constant term")
	}
	if _, err := newKeygenCommitmentsFromPoints([]*fed.Point{generator, identity}, 2); err != nil {
		t.Fatalf("keygen commitments rejected identity higher coefficient: %v", err)
	}
	if _, err := newReshareCommitmentsFromPoints([]*fed.Point{identity, identity}, 2); err != nil {
		t.Fatalf("reshare commitments rejected identity: %v", err)
	}
	if _, err := newGroupCommitmentsFromPoints([]*fed.Point{identity, generator}, 2); err == nil {
		t.Fatal("group commitments accepted identity public key")
	}
}

func TestKeygenCommitmentsWireCodec(t *testing.T) {
	t.Parallel()

	commitments, err := newKeygenCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint(), fed.NewIdentityPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := commitments.MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if want := wire.EncodeBytesList(commitments.BytesList()); !bytes.Equal(raw, want) {
		t.Fatalf("custom encoding changed byteslist value:\n got %x\nwant %x", raw, want)
	}

	var decoded keygenCommitments
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatal(err)
	}
	if !commitments.Equal(decoded) {
		t.Fatal("keygen commitments changed across custom codec round trip")
	}
}

func TestReshareCommitmentsWireCodec(t *testing.T) {
	t.Parallel()

	commitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewIdentityPoint(), fed.NewGeneratorPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := commitments.MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if want := wire.EncodeBytesList(commitments.BytesList()); !bytes.Equal(raw, want) {
		t.Fatalf("custom encoding changed byteslist value:\n got %x\nwant %x", raw, want)
	}

	var decoded reshareCommitments
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatal(err)
	}
	if !commitments.Equal(decoded) {
		t.Fatal("reshare commitments changed across custom codec round trip")
	}
}

func TestCommitmentValidateThresholdRejectsUndercount(t *testing.T) {
	t.Parallel()

	keygenCommitments, err := newKeygenCommitmentsFromPoints([]*fed.Point{fed.NewGeneratorPoint()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := keygenCommitments.ValidateThreshold(2); err == nil {
		t.Fatal("keygen commitments accepted count below threshold")
	}

	reshareCommitments, err := newReshareCommitmentsFromPoints([]*fed.Point{fed.NewIdentityPoint()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := reshareCommitments.ValidateThreshold(2); err == nil {
		t.Fatal("reshare commitments accepted count below threshold")
	}
}

func TestGroupCommitmentsWireCodec(t *testing.T) {
	t.Parallel()

	group, err := newGroupCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint(), fed.NewIdentityPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := group.MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if want := wire.EncodeBytesList(group.BytesList()); !bytes.Equal(raw, want) {
		t.Fatalf("custom encoding changed byteslist value:\n got %x\nwant %x", raw, want)
	}

	var decoded groupCommitments
	if err := decoded.UnmarshalWireValue(raw); err != nil {
		t.Fatal(err)
	}
	if !group.Equal(decoded) {
		t.Fatal("group commitments changed across custom codec round trip")
	}
}

func TestGroupCommitmentsWireCodecRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	generator := fed.NewGeneratorPoint().Bytes()
	identity := fed.NewIdentityPoint().Bytes()
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "identity constant term",
			raw:  wire.EncodeBytesList([][]byte{identity, generator}),
		},
		{
			name: "short item",
			raw:  wire.EncodeBytesList([][]byte{generator[:ed25519CommitmentBytes-1]}),
		},
		{
			name: "long item",
			raw:  wire.EncodeBytesList([][]byte{append(append([]byte(nil), generator...), 0)}),
		},
		{
			name: "trailing data",
			raw:  append(wire.EncodeBytesList([][]byte{generator}), 0),
		},
		{
			name: "empty list",
			raw:  wire.EncodeBytesList(nil),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var decoded groupCommitments
			if err := decoded.UnmarshalWireValue(tc.raw); err == nil {
				t.Fatal("expected decode error")
			}
		})
	}
}

func TestGroupCommitmentsCustomEncodingMatchesBytesList(t *testing.T) {
	t.Parallel()

	group, err := newGroupCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint(), fed.NewIdentityPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	limits := wire.FieldLimits{"threshold": 2, "point": ed25519CommitmentBytes}
	oldRaw, err := wire.Marshal(
		oldGroupCommitmentsWire{
			Threshold:        2,
			GroupCommitments: group.BytesList(),
		},
		wire.WithFieldLimitsForMarshal(limits),
	)
	if err != nil {
		t.Fatal(err)
	}
	newRaw, err := wire.Marshal(
		newGroupCommitmentsWire{
			Threshold:        2,
			GroupCommitments: group.Clone(),
		},
		wire.WithFieldLimitsForMarshal(limits),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldRaw, newRaw) {
		t.Fatalf("custom field changed message bytes:\n old %x\n new %x", oldRaw, newRaw)
	}

	var newDecoded newGroupCommitmentsWire
	if err := wire.Unmarshal(oldRaw, &newDecoded, wire.WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
	if !group.Equal(newDecoded.GroupCommitments) {
		t.Fatal("new custom field did not decode old byteslist encoding")
	}

	var oldDecoded oldGroupCommitmentsWire
	if err := wire.Unmarshal(newRaw, &oldDecoded, wire.WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
	if got := wire.EncodeBytesList(oldDecoded.GroupCommitments); !bytes.Equal(got, wire.EncodeBytesList(group.BytesList())) {
		t.Fatal("old byteslist field did not decode new custom encoding")
	}
}

func TestCommitmentsPayloadCustomEncodingMatchesBytesList(t *testing.T) {
	t.Parallel()

	limits := testLimits().fieldLimits()
	chainCodeCommit := bytes.Repeat([]byte{0x91}, 32)
	planHash := bytes.Repeat([]byte{0x90}, 32)

	keygenCommitments, err := newKeygenCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint(), fed.NewIdentityPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldKeygenRaw, err := wire.Marshal(
		oldKeygenCommitmentsPayloadWire{
			Commitments:     keygenCommitments.BytesList(),
			ChainCodeCommit: chainCodeCommit,
			PlanHash:        planHash,
		},
		wire.WithFieldLimitsForMarshal(limits),
	)
	if err != nil {
		t.Fatal(err)
	}
	newKeygenRaw, err := marshalKeygenCommitmentsPayload(
		keygenCommitmentsPayload{
			Commitments:     keygenCommitments.Clone(),
			ChainCodeCommit: chainCodeCommit,
			PlanHash:        planHash,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldKeygenRaw, newKeygenRaw) {
		t.Fatalf("custom keygen commitments changed payload bytes:\n old %x\n new %x", oldKeygenRaw, newKeygenRaw)
	}
	keygenDecoded, err := unmarshalKeygenCommitmentsPayload(oldKeygenRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !keygenCommitments.Equal(keygenDecoded.Commitments) {
		t.Fatal("keygen custom field did not decode old byteslist encoding")
	}
	var oldKeygenDecoded oldKeygenCommitmentsPayloadWire
	if err := wire.Unmarshal(newKeygenRaw, &oldKeygenDecoded, wire.WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
	if got := wire.EncodeBytesList(oldKeygenDecoded.Commitments); !bytes.Equal(got, wire.EncodeBytesList(keygenCommitments.BytesList())) {
		t.Fatal("old keygen byteslist field did not decode new custom encoding")
	}

	reshareCommitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewIdentityPoint(), fed.NewGeneratorPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldReshareRaw, err := wire.Marshal(
		oldReshareCommitmentsPayloadWire{
			Commitments: reshareCommitments.BytesList(),
			PlanHash:    planHash,
		},
		wire.WithFieldLimitsForMarshal(limits),
	)
	if err != nil {
		t.Fatal(err)
	}
	newReshareRaw, err := marshalReshareCommitmentsPayload(
		reshareCommitmentsPayload{
			Commitments: reshareCommitments.Clone(),
			PlanHash:    planHash,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldReshareRaw, newReshareRaw) {
		t.Fatalf("custom reshare commitments changed payload bytes:\n old %x\n new %x", oldReshareRaw, newReshareRaw)
	}
	reshareDecoded, err := unmarshalReshareCommitmentsPayload(oldReshareRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !reshareCommitments.Equal(reshareDecoded.Commitments) {
		t.Fatal("reshare custom field did not decode old byteslist encoding")
	}
	var oldReshareDecoded oldReshareCommitmentsPayloadWire
	if err := wire.Unmarshal(newReshareRaw, &oldReshareDecoded, wire.WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
	if got := wire.EncodeBytesList(oldReshareDecoded.Commitments); !bytes.Equal(got, wire.EncodeBytesList(reshareCommitments.BytesList())) {
		t.Fatal("old reshare byteslist field did not decode new custom encoding")
	}
}

func TestCommitmentsPayloadCustomCommitmentsEnforceResourceLimit(t *testing.T) {
	t.Parallel()

	keygenCommitments, err := newKeygenCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint(), fed.NewIdentityPoint(), fed.NewIdentityPoint()},
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	reshareCommitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewIdentityPoint(), fed.NewGeneratorPoint(), fed.NewIdentityPoint()},
		3,
	)
	if err != nil {
		t.Fatal(err)
	}

	marshalLimits := testLimits().fieldLimits()
	planHash := bytes.Repeat([]byte{0x90}, 32)
	keygenRaw, err := wire.Marshal(
		oldKeygenCommitmentsPayloadWire{
			Commitments:     keygenCommitments.BytesList(),
			ChainCodeCommit: bytes.Repeat([]byte{0x91}, 32),
			PlanHash:        planHash,
		},
		wire.WithFieldLimitsForMarshal(marshalLimits),
	)
	if err != nil {
		t.Fatal(err)
	}
	reshareRaw, err := wire.Marshal(
		oldReshareCommitmentsPayloadWire{
			Commitments: reshareCommitments.BytesList(),
			PlanHash:    planHash,
		},
		wire.WithFieldLimitsForMarshal(marshalLimits),
	)
	if err != nil {
		t.Fatal(err)
	}

	decodeLimits := testLimits()
	decodeLimits.Threshold.MaxThreshold = 2
	tests := []struct {
		name   string
		raw    []byte
		decode func([]byte, Limits) error
	}{
		{
			name: "keygen",
			raw:  keygenRaw,
			decode: func(raw []byte, limits Limits) error {
				var payload keygenCommitmentsPayload
				return payload.UnmarshalBinaryWithLimits(raw, limits)
			},
		},
		{
			name: "reshare",
			raw:  reshareRaw,
			decode: func(raw []byte, limits Limits) error {
				var payload reshareCommitmentsPayload
				return payload.UnmarshalBinaryWithLimits(raw, limits)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.decode(tc.raw, decodeLimits)
			if err == nil {
				t.Fatal("payload accepted commitments over resource limit")
			}
			if !strings.Contains(err.Error(), "custom item count") ||
				!strings.Contains(err.Error(), "exceeds max_items") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSemanticCommitmentEvaluationMatchesCurveHelper(t *testing.T) {
	t.Parallel()
	points := []*fed.Point{
		fed.NewGeneratorPoint(),
		fed.NewIdentityPoint().ScalarBaseMult(edcurve.ScalarFromUint64(7)),
	}
	group, err := newGroupCommitmentsFromPoints(points, len(points))
	if err != nil {
		t.Fatal(err)
	}
	got, err := group.Eval(tss.PartyID(3))
	if err != nil {
		t.Fatal(err)
	}
	want, err := edcurve.EvalCommitments(group.BytesList(), 3)
	if err != nil {
		t.Fatal(err)
	}
	wantPoint, err := newVerificationSharePointFromBytes(want)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(wantPoint) {
		t.Fatal("semantic commitment evaluation mismatch")
	}
}

func TestSemanticCommitmentBytesAreOwned(t *testing.T) {
	t.Parallel()
	group, err := newGroupCommitmentsFromPoints([]*fed.Point{fed.NewGeneratorPoint()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	first := group.BytesList()
	first[0][0] ^= 1
	second := group.BytesList()
	if first[0][0] == second[0][0] {
		t.Fatal("BytesList exposed mutable internal state")
	}
	clone := group.Clone()
	if !group.Equal(clone) {
		t.Fatal("group commitment clone mismatch")
	}
}
