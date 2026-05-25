package codec

import (
	"bytes"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestWireFieldHelpers(t *testing.T) {
	fields := []wire.Field{
		{Tag: 1, Value: Uint32(7)},
		{Tag: 2, Value: Bool(true)},
		{Tag: 3, Value: EncodeUint32List([]testID{1, 2})},
		{Tag: 4, Value: EncodeBytesList([][]byte{{3}})},
		{Tag: 5, Value: EncodePartyBytes([]PartyBytes[testID]{{Party: 1, Bytes: []byte{4}}})},
		{Tag: 6, Value: EncodePartyBytePairs([]PartyBytePair[testID]{{Party: 1, First: []byte{5}, Second: []byte{6}}})},
	}
	if err := RequireExactTags(fields, 1, 2, 3, 4, 5, 6); err != nil {
		t.Fatal(err)
	}
	if got, err := Uint32Field(fields, 1); err != nil || got != 7 {
		t.Fatalf("Uint32Field got %d, %v", got, err)
	}
	if got, err := BoolField(fields, 2); err != nil || !got {
		t.Fatalf("BoolField got %v, %v", got, err)
	}
	if got := MustField(fields, 1); !bytes.Equal(got, Uint32(7)) {
		t.Fatalf("MustField got %x", got)
	}
	if got, err := Uint32ListField[testID](fields, 3); err != nil || len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("Uint32ListField got %v, %v", got, err)
	}
	if got, err := BytesListField(fields, 4); err != nil || len(got) != 1 || !bytes.Equal(got[0], []byte{3}) {
		t.Fatalf("BytesListField got %x, %v", got, err)
	}
	if got, err := PartyBytesField[testID](fields, 5, "verification share"); err != nil || len(got) != 1 || got[0].Party != 1 || !bytes.Equal(got[0].Bytes, []byte{4}) {
		t.Fatalf("PartyBytesField got %#v, %v", got, err)
	}
	if got, err := PartyBytePairsField[testID](fields, 6, "Paillier public share"); err != nil || len(got) != 1 || got[0].Party != 1 || !bytes.Equal(got[0].First, []byte{5}) || !bytes.Equal(got[0].Second, []byte{6}) {
		t.Fatalf("PartyBytePairsField got %#v, %v", got, err)
	}
}

func TestWireFieldHelperErrors(t *testing.T) {
	fields := []wire.Field{{Tag: 1, Value: Uint32(7)}}
	if err := RequireExactTags(fields, 2); err == nil {
		t.Fatal("RequireExactTags accepted wrong tag")
	}
	if _, err := Uint32Field([]wire.Field{{Tag: 1, Value: append(Uint32(7), 0)}}, 1); err == nil {
		t.Fatal("Uint32Field accepted trailing bytes")
	}
	if _, err := BoolField([]wire.Field{{Tag: 1, Value: []byte{2}}}, 1); err == nil {
		t.Fatal("BoolField accepted non-canonical bool")
	}
}
