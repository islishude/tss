package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

var magic = []byte{'T', 'S', 'S', '1'}

// Field is one canonical TLV field with a strictly increasing tag.
type Field struct {
	Tag   uint16
	Value []byte
}

// Marshal encodes a typed message and rejects unsorted or duplicate tags.
func Marshal(version uint16, typeID string, fields []Field) ([]byte, error) {
	if typeID == "" {
		return nil, errors.New("empty wire type id")
	}
	if !utf8.ValidString(typeID) {
		return nil, errors.New("wire type id must be valid UTF-8")
	}
	if len(typeID) > math.MaxUint16 {
		return nil, errors.New("wire type id too long")
	}
	if len(fields) > math.MaxUint16 {
		return nil, errors.New("too many wire fields")
	}
	var last uint16
	for i, field := range fields {
		if field.Value == nil {
			return nil, fmt.Errorf("nil wire field %d", field.Tag)
		}
		if len(field.Value) > math.MaxUint32 {
			return nil, fmt.Errorf("wire field %d too large", field.Tag)
		}
		if i > 0 && field.Tag <= last {
			return nil, errors.New("wire fields must be strictly increasing")
		}
		last = field.Tag
	}
	size := len(magic) + 2 + len(typeID) + 2 + 2
	for _, field := range fields {
		size += 2 + 4 + len(field.Value)
	}
	out := make([]byte, 0, size)
	out = append(out, magic...)
	out = appendUint16(out, uint16(len(typeID)))
	out = append(out, typeID...)
	out = appendUint16(out, version)
	out = appendUint16(out, uint16(len(fields)))
	for _, field := range fields {
		out = appendUint16(out, field.Tag)
		out = appendUint32(out, uint32(len(field.Value)))
		out = append(out, field.Value...)
	}
	return out, nil
}

// Unmarshal decodes a typed message and rejects trailing or non-canonical data.
func Unmarshal(in []byte, expectedTypeID string) (uint16, []Field, error) {
	if expectedTypeID == "" {
		return 0, nil, errors.New("empty expected wire type id")
	}
	if len(in) < len(magic)+2+2+2 {
		return 0, nil, errors.New("wire input too short")
	}
	if !bytes.Equal(in[:len(magic)], magic) {
		return 0, nil, errors.New("invalid wire magic")
	}
	offset := len(magic)
	typeLen, offset, err := readUint16(in, offset)
	if err != nil {
		return 0, nil, err
	}
	if typeLen == 0 {
		return 0, nil, errors.New("empty wire type id")
	}
	if len(in)-offset < int(typeLen) {
		return 0, nil, errors.New("truncated wire type id")
	}
	typeID := string(in[offset : offset+int(typeLen)])
	if !utf8.ValidString(typeID) {
		return 0, nil, errors.New("wire type id must be valid UTF-8")
	}
	if typeID != expectedTypeID {
		return 0, nil, fmt.Errorf("unexpected wire type id %q", typeID)
	}
	offset += int(typeLen)
	version, offset, err := readUint16(in, offset)
	if err != nil {
		return 0, nil, err
	}
	fieldCount, offset, err := readUint16(in, offset)
	if err != nil {
		return 0, nil, err
	}
	fields := make([]Field, 0, fieldCount)
	var last uint16
	for i := 0; i < int(fieldCount); i++ {
		tag, next, err := readUint16(in, offset)
		if err != nil {
			return 0, nil, err
		}
		if i > 0 && tag <= last {
			return 0, nil, errors.New("wire fields must be strictly increasing")
		}
		offset = next
		length, next, err := readUint32(in, offset)
		if err != nil {
			return 0, nil, err
		}
		offset = next
		if uint64(len(in)-offset) < uint64(length) {
			return 0, nil, fmt.Errorf("truncated wire field %d", tag)
		}
		value := make([]byte, length)
		copy(value, in[offset:offset+int(length)])
		fields = append(fields, Field{Tag: tag, Value: value})
		offset += int(length)
		last = tag
	}
	if offset != len(in) {
		return 0, nil, errors.New("trailing bytes after wire message")
	}
	return version, fields, nil
}

// Find returns a copy of a field value by tag.
func Find(fields []Field, tag uint16) ([]byte, bool) {
	for _, field := range fields {
		if field.Tag == tag {
			value := make([]byte, len(field.Value))
			copy(value, field.Value)
			return value, true
		}
	}
	return nil, false
}

// Require returns a field value or an error when the tag is absent.
func Require(fields []Field, tag uint16) ([]byte, error) {
	value, ok := Find(fields, tag)
	if !ok {
		return nil, fmt.Errorf("missing wire field %d", tag)
	}
	return value, nil
}

func appendUint16(out []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(out, buf[:]...)
}

func appendUint32(out []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(out, buf[:]...)
}

func readUint16(in []byte, offset int) (uint16, int, error) {
	if len(in)-offset < 2 {
		return 0, offset, errors.New("truncated uint16")
	}
	return binary.BigEndian.Uint16(in[offset : offset+2]), offset + 2, nil
}

func readUint32(in []byte, offset int) (uint32, int, error) {
	if len(in)-offset < 4 {
		return 0, offset, errors.New("truncated uint32")
	}
	return binary.BigEndian.Uint32(in[offset : offset+4]), offset + 4, nil
}
