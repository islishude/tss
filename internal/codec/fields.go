package codec

import (
	"errors"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

// Uint32Field decodes an exact-length uint32 from a required wire field.
func Uint32Field(fields []wire.Field, tag uint16) (uint32, error) {
	raw, err := wire.Require(fields, tag)
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
func BoolField(fields []wire.Field, tag uint16) (bool, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return false, err
	}
	return DecodeBool(raw)
}

// MustField returns a required field value when tags were already checked.
func MustField(fields []wire.Field, tag uint16) []byte {
	value, _ := wire.Require(fields, tag)
	return value
}

// RequireExactTags requires fields to contain exactly the provided tag sequence.
func RequireExactTags(fields []wire.Field, tags ...uint16) error {
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
