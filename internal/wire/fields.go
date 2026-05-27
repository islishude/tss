package wire

import (
	"errors"
	"fmt"
)

// RequireExactTags requires fields to contain exactly the provided tag sequence.
func RequireExactTags(fields []Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("got %d fields, want %d", len(fields), len(tags))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected field tag %d at index %d", fields[i].Tag, i)
		}
	}
	return nil
}

// MustField returns a required field value when tags were already checked.
func MustField(fields []Field, tag uint16) []byte {
	value, _ := Require(fields, tag)
	return value
}

// Uint32Field decodes an exact-length uint32 from a required wire field.
func Uint32Field(fields []Field, tag uint16) (uint32, error) {
	raw, err := Require(fields, tag)
	if err != nil {
		return 0, err
	}
	value, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return 0, err
	}
	if offset != len(raw) {
		return 0, errors.New("trailing uint32 bytes")
	}
	return value, nil
}

// BoolField decodes a bool from a required wire field.
func BoolField(fields []Field, tag uint16) (bool, error) {
	raw, err := Require(fields, tag)
	if err != nil {
		return false, err
	}
	return DecodeBool(raw)
}

// Uint32ListField decodes a uint32-compatible list from a required wire field.
func Uint32ListField[T uint32Value](fields []Field, tag uint16) ([]T, error) {
	raw, err := Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodeUint32List[T](raw)
}

// BytesListField decodes a byte-string list from a required wire field.
func BytesListField(fields []Field, tag uint16) ([][]byte, error) {
	raw, err := Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodeBytesList(raw)
}

// PartyBytesField decodes party-scoped byte string records from a wire field.
func PartyBytesField[T uint32Value](fields []Field, tag uint16, name string) ([]PartyBytes[T], error) {
	raw, err := Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodePartyBytes[T](raw, name)
}

// PartyBytePairsField decodes party-scoped byte string pairs from a wire field.
func PartyBytePairsField[T uint32Value](fields []Field, tag uint16, name string) ([]PartyBytePair[T], error) {
	raw, err := Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodePartyBytePairs[T](raw, name)
}
