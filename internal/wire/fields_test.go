package wire

import (
	"bytes"
	"testing"
)

type testID uint32

func TestWireFieldHelpers(t *testing.T) {
	fields := []Field{
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
	// Tags validated; access fields by index via Decode* functions.
	if got, err := DecodeUint32(fields[0].Value); err != nil || got != 7 {
		t.Fatalf("DecodeUint32 got %d, %v", got, err)
	}
	if got, err := DecodeBool(fields[1].Value); err != nil || !got {
		t.Fatalf("DecodeBool got %v, %v", got, err)
	}
	if got, err := DecodeUint32List[testID](fields[2].Value); err != nil || len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("DecodeUint32List got %v, %v", got, err)
	}
	if got, err := DecodeBytesList(fields[3].Value); err != nil || len(got) != 1 || !bytes.Equal(got[0], []byte{3}) {
		t.Fatalf("DecodeBytesList got %x, %v", got, err)
	}
	if got, err := DecodePartyBytes[testID](fields[4].Value, "verification share"); err != nil || len(got) != 1 || got[0].Party != 1 || !bytes.Equal(got[0].Bytes, []byte{4}) {
		t.Fatalf("DecodePartyBytes got %#v, %v", got, err)
	}
	if got, err := DecodePartyBytePairs[testID](fields[5].Value, "Paillier public share"); err != nil || len(got) != 1 || got[0].Party != 1 || !bytes.Equal(got[0].First, []byte{5}) || !bytes.Equal(got[0].Second, []byte{6}) {
		t.Fatalf("DecodePartyBytePairs got %#v, %v", got, err)
	}
}

func TestWireFieldHelperErrors(t *testing.T) {
	fields := []Field{{Tag: 1, Value: Uint32(7)}}
	if err := RequireExactTags(fields, 2); err == nil {
		t.Fatal("RequireExactTags accepted wrong tag")
	}
}
