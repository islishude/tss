package codec

import (
	"errors"

	"github.com/islishude/tss/internal/wire"
)

// NonNilBytes returns an empty byte slice when in is nil.
func NonNilBytes(in []byte) []byte {
	if in == nil {
		return []byte{}
	}
	return in
}

// ReadBytes reads a uint32 length-prefixed byte string at offset.
func ReadBytes(in []byte, offset int) ([]byte, int, error) {
	length, offset, err := ReadUint32(in, offset)
	if err != nil {
		return nil, offset, err
	}
	if uint64(len(in)-offset) < uint64(length) {
		return nil, offset, errors.New("truncated byte field")
	}
	out := make([]byte, length)
	copy(out, in[offset:offset+int(length)])
	return out, offset + int(length), nil
}

// AppendBytes appends a uint32 length-prefixed byte string to out.
func AppendBytes(out, value []byte) []byte {
	out = append(out, Uint32(uint32(len(value)))...)
	return append(out, value...)
}

// EncodeBytesList encodes a list of byte strings with uint32 lengths.
func EncodeBytesList(items [][]byte) []byte {
	out := Uint32(uint32(len(items)))
	for _, item := range items {
		out = AppendBytes(out, item)
	}
	return out
}

// DecodeBytesList decodes a list produced by EncodeBytesList.
func DecodeBytesList(raw []byte) ([][]byte, error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, count)
	for i := 0; i < int(count); i++ {
		item, next, err := ReadBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, item)
	}
	if offset != len(raw) {
		return nil, errors.New("trailing bytes list data")
	}
	return out, nil
}

// BytesListField decodes a byte-string list from a required wire field.
func BytesListField(fields []wire.Field, tag uint16) ([][]byte, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodeBytesList(raw)
}
