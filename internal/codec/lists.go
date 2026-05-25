package codec

import (
	"errors"

	"github.com/islishude/tss/internal/wire"
)

// EncodeUint32List encodes a list of uint32-compatible values.
func EncodeUint32List[T uint32Value](items []T) []byte {
	out := Uint32(uint32(len(items)))
	for _, item := range items {
		out = append(out, Uint32(uint32(item))...)
	}
	return out
}

// DecodeUint32List decodes a list produced by EncodeUint32List.
func DecodeUint32List[T uint32Value](raw []byte) ([]T, error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if uint64(len(raw)-offset) != uint64(count)*4 {
		return nil, errors.New("invalid party id list length")
	}
	out := make([]T, 0, count)
	for i := 0; i < int(count); i++ {
		value, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, T(value))
	}
	return out, nil
}

// Uint32ListField decodes a uint32-compatible list from a required wire field.
func Uint32ListField[T uint32Value](fields []wire.Field, tag uint16) ([]T, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodeUint32List[T](raw)
}
