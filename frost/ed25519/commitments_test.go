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

const testFROSTGroupCommitmentsType = "test.frost.group-commitments"

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
	oldValue := wire.EncodeBytesList(group.BytesList())
	newValue, err := group.Clone().MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldValue, newValue) {
		t.Fatalf("custom group commitments changed field bytes:\n old %x\n new %x", oldValue, newValue)
	}
	oldRaw, err := wire.MarshalFields(1, testFROSTGroupCommitmentsType, []wire.Field{
		{Tag: 1, Value: wire.Uint32(2)},
		{Tag: 2, Value: oldValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	newRaw, err := wire.MarshalFields(1, testFROSTGroupCommitmentsType, []wire.Field{
		{Tag: 1, Value: wire.Uint32(2)},
		{Tag: 2, Value: newValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldRaw, newRaw) {
		t.Fatalf("custom field changed message bytes:\n old %x\n new %x", oldRaw, newRaw)
	}

	_, fields, err := wire.UnmarshalFields(oldRaw, testFROSTGroupCommitmentsType)
	if err != nil {
		t.Fatal(err)
	}
	var decoded groupCommitments
	if err := decoded.UnmarshalWireValue(fields[1].Value); err != nil {
		t.Fatal(err)
	}
	if !group.Equal(decoded) {
		t.Fatal("new custom field did not decode old byteslist encoding")
	}
	_, fields, err = wire.UnmarshalFields(newRaw, testFROSTGroupCommitmentsType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fields[1].Value, wire.EncodeBytesList(group.BytesList())) {
		t.Fatal("custom field no longer matches byteslist encoding")
	}
}

func TestCommitmentsPayloadCustomEncodingMatchesBytesList(t *testing.T) {
	t.Parallel()

	chainCodeCommit := bytes.Repeat([]byte{0x91}, 32)
	planHash := bytes.Repeat([]byte{0x90}, 32)

	keygenCommitments, err := newKeygenCommitmentsFromPoints(
		[]*fed.Point{fed.NewGeneratorPoint(), fed.NewIdentityPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldKeygenRaw, err := wire.MarshalFields(
		keygenCommitmentsPayloadWireVersion,
		keygenCommitmentsPayloadWireType,
		[]wire.Field{
			{Tag: 1, Value: wire.EncodeBytesList(keygenCommitments.BytesList())},
			{Tag: 2, Value: chainCodeCommit},
			{Tag: 3, Value: planHash},
		},
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
	_, keygenFields, err := wire.UnmarshalFields(newKeygenRaw, keygenCommitmentsPayloadWireType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keygenFields[0].Value, wire.EncodeBytesList(keygenCommitments.BytesList())) {
		t.Fatal("keygen custom field no longer matches byteslist encoding")
	}

	reshareCommitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewIdentityPoint(), fed.NewGeneratorPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldReshareRaw, err := wire.MarshalFields(
		reshareCommitmentsPayloadWireVersion,
		reshareCommitmentsPayloadWireType,
		[]wire.Field{
			{Tag: 1, Value: wire.EncodeBytesList(reshareCommitments.BytesList())},
			{Tag: 2, Value: planHash},
		},
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
	_, reshareFields, err := wire.UnmarshalFields(newReshareRaw, reshareCommitmentsPayloadWireType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reshareFields[0].Value, wire.EncodeBytesList(reshareCommitments.BytesList())) {
		t.Fatal("reshare custom field no longer matches byteslist encoding")
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

	planHash := bytes.Repeat([]byte{0x90}, 32)
	keygenRaw, err := wire.MarshalFields(
		keygenCommitmentsPayloadWireVersion,
		keygenCommitmentsPayloadWireType,
		[]wire.Field{
			{Tag: 1, Value: wire.EncodeBytesList(keygenCommitments.BytesList())},
			{Tag: 2, Value: bytes.Repeat([]byte{0x91}, 32)},
			{Tag: 3, Value: planHash},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	reshareRaw, err := wire.MarshalFields(
		reshareCommitmentsPayloadWireVersion,
		reshareCommitmentsPayloadWireType,
		[]wire.Field{
			{Tag: 1, Value: wire.EncodeBytesList(reshareCommitments.BytesList())},
			{Tag: 2, Value: planHash},
		},
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
