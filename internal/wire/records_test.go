package wire

import (
	"bytes"
	"slices"
	"testing"
)

func TestUint32List(t *testing.T) {
	input := []testID{3, 7, 11}
	raw := EncodeUint32List(input)
	got, err := DecodeUint32List[testID](raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, input) {
		t.Fatalf("DecodeUint32List got %v", got)
	}
	if _, err := DecodeUint32List[testID]([]byte{0, 0, 0, 1, 0}); err == nil {
		t.Fatal("DecodeUint32List accepted invalid length")
	}
}

func TestBytesList(t *testing.T) {
	items := [][]byte{{1}, {}, {2, 3}}
	raw := EncodeBytesList(items)
	got, err := DecodeBytesList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(items) {
		t.Fatalf("got %d items", len(got))
	}
	for i := range items {
		if !bytes.Equal(got[i], items[i]) {
			t.Fatalf("item %d got %x", i, got[i])
		}
	}
	if _, err := DecodeBytesList(append(raw, 0)); err == nil {
		t.Fatal("DecodeBytesList accepted trailing bytes")
	}
}

func TestPartyBytes(t *testing.T) {
	input := []PartyBytes[testID]{
		{Party: 1, Bytes: []byte{1, 2}},
		{Party: 2, Bytes: []byte{}},
	}
	raw := EncodePartyBytes(input)
	got, err := DecodePartyBytes[testID](raw, "verification share")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(input) {
		t.Fatalf("got %d records", len(got))
	}
	for i := range input {
		if got[i].Party != input[i].Party || !bytes.Equal(got[i].Bytes, input[i].Bytes) {
			t.Fatalf("record %d got %#v", i, got[i])
		}
	}
	if _, err := DecodePartyBytes[testID](append(raw, 0), "verification share"); err == nil {
		t.Fatal("DecodePartyBytes accepted trailing bytes")
	}
}

func TestPartyBytePairs(t *testing.T) {
	input := []PartyBytePair[testID]{
		{Party: 1, First: []byte{1}, Second: []byte{2}},
		{Party: 2, First: []byte{}, Second: []byte{3, 4}},
	}
	raw := EncodePartyBytePairs(input)
	got, err := DecodePartyBytePairs[testID](raw, "Paillier public share")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(input) {
		t.Fatalf("got %d records", len(got))
	}
	for i := range input {
		if got[i].Party != input[i].Party || !bytes.Equal(got[i].First, input[i].First) || !bytes.Equal(got[i].Second, input[i].Second) {
			t.Fatalf("record %d got %#v", i, got[i])
		}
	}
	if _, err := DecodePartyBytePairs[testID](append(raw, 0), "Paillier public share"); err == nil {
		t.Fatal("DecodePartyBytePairs accepted trailing bytes")
	}
}
