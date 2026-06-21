package wire

import (
	"bytes"
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

// MarshalFields encodes a typed message and rejects unsorted or duplicate tags.
func MarshalFields(version uint16, typeID string, fields []Field) ([]byte, error) {
	if typeID == "" {
		return nil, errors.New("empty wire type id")
	}
	if !utf8.ValidString(typeID) {
		return nil, errors.New("wire type id must be valid UTF-8")
	}
	if len(typeID) > math.MaxUint16 {
		return nil, errors.New("wire type id too long")
	}

	body, err := marshalFieldBody(fields)
	if err != nil {
		return nil, err
	}

	size := len(magic) + 2 + len(typeID) + 2 + len(body)
	out := make([]byte, 0, size)
	out = append(out, magic...)
	out = AppendUint16(out, uint16(len(typeID)))
	out = append(out, typeID...)
	out = AppendUint16(out, version)
	out = append(out, body...)
	return out, nil
}

// marshalFieldBody encodes a list of fields into the canonical field body format:
//
//	uint16 field_count
//	repeat field_count:
//	    uint16 tag
//	    uint32 value_len
//	    value bytes
//
// It validates field ordering, nil rejection, and size limits.
func marshalFieldBody(fields []Field) ([]byte, error) {
	if len(fields) > math.MaxUint16 {
		return nil, errors.New("too many wire fields")
	}
	var last uint16
	for i, field := range fields {
		if field.Tag == 0 {
			return nil, errors.New("wire field tag 0 is invalid")
		}
		if field.Value == nil {
			return nil, fmt.Errorf("nil wire field %d", field.Tag)
		}
		if uint64(len(field.Value)) > math.MaxUint32 {
			return nil, fmt.Errorf("wire field %d too large", field.Tag)
		}
		if i > 0 && field.Tag <= last {
			return nil, errors.New("wire fields must be strictly increasing")
		}
		last = field.Tag
	}
	size := 2 // field count
	for _, field := range fields {
		size += 2 + 4 + len(field.Value)
	}
	out := make([]byte, 0, size)
	out = AppendUint16(out, uint16(len(fields)))
	for _, field := range fields {
		out = AppendUint16(out, field.Tag)
		out = AppendUint32(out, uint32(len(field.Value)))
		out = append(out, field.Value...)
	}
	return out, nil
}

// FrameLimits defines per-message caps used during TLV decoding.
type FrameLimits struct {
	MaxTotalBytes int // maximum input byte length
	MaxFields     int // maximum TLV field count
	MaxFieldBytes int // maximum per-field value size
}

// DefaultFrameLimits returns conservative wire-level caps suitable as a fallback.
func DefaultFrameLimits() FrameLimits {
	return FrameLimits{
		MaxTotalBytes: 1 << 20, // 1 MiB
		MaxFields:     256,
		MaxFieldBytes: 1 << 20, // 1 MiB
	}
}

func (l FrameLimits) withDefaults() FrameLimits {
	defaults := DefaultFrameLimits()
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if l.MaxFields == 0 {
		l.MaxFields = defaults.MaxFields
	}
	if l.MaxFieldBytes == 0 {
		l.MaxFieldBytes = defaults.MaxFieldBytes
	}
	return l
}

func (l FrameLimits) validate() error {
	if l.MaxTotalBytes <= 0 {
		return errors.New("wire MaxTotalBytes must be positive")
	}
	if l.MaxFields <= 0 {
		return errors.New("wire MaxFields must be positive")
	}
	if l.MaxFieldBytes <= 0 {
		return errors.New("wire MaxFieldBytes must be positive")
	}
	return nil
}

// UnmarshalFields decodes a typed message and rejects trailing or non-canonical data.
// It uses DefaultFrameLimits to guard against oversized inputs.
func UnmarshalFields(in []byte, expectedTypeID string) (uint16, []Field, error) {
	return UnmarshalFieldsWithLimits(in, expectedTypeID, DefaultFrameLimits())
}

// UnmarshalFieldsWithLimits decodes a typed TLV message enforcing per-message caps.
// It checks the total input size, field count, and per-field value size before
// allocating memory, preventing oversized messages from causing OOM.
func UnmarshalFieldsWithLimits(in []byte, expectedTypeID string, limits FrameLimits) (uint16, []Field, error) {
	limits = limits.withDefaults()
	if err := limits.validate(); err != nil {
		return 0, nil, err
	}
	if expectedTypeID == "" {
		return 0, nil, errors.New("empty expected wire type id")
	}
	if len(in) < len(magic)+2+2+2 {
		return 0, nil, errors.New("wire input too short")
	}
	if len(in) > limits.MaxTotalBytes {
		return 0, nil, fmt.Errorf("wire input too large: %d > %d", len(in), limits.MaxTotalBytes)
	}
	if !bytes.Equal(in[:len(magic)], magic) {
		return 0, nil, errors.New("invalid wire magic")
	}
	offset := len(magic)
	typeLen, offset, err := ReadUint16(in, offset)
	if err != nil {
		return 0, nil, err
	}
	if typeLen == 0 {
		return 0, nil, errors.New("empty wire type id")
	}
	if uint64(len(in)-offset) < uint64(typeLen) {
		return 0, nil, errors.New("truncated wire type id")
	}
	typeLenInt := int(typeLen)
	typeID := string(in[offset : offset+typeLenInt])
	if !utf8.ValidString(typeID) {
		return 0, nil, errors.New("wire type id must be valid UTF-8")
	}
	if typeID != expectedTypeID {
		return 0, nil, fmt.Errorf("unexpected wire type id %q", typeID)
	}
	offset += typeLenInt
	version, offset, err := ReadUint16(in, offset)
	if err != nil {
		return 0, nil, err
	}

	fields, newOffset, err := unmarshalFieldBody(in, offset, limits, typeID)
	if err != nil {
		return 0, nil, err
	}

	if newOffset != len(in) {
		return 0, nil, errors.New("trailing bytes after wire message")
	}
	return version, fields, nil
}

// unmarshalFieldBody decodes a field body starting at offset in raw.
// It validates field count, tag ordering, value sizes, and trailing bytes.
// The returned fields each own their value bytes (copied from raw).
// It returns the new offset after the field body.
func unmarshalFieldBody(raw []byte, offset int, limits FrameLimits, name string) ([]Field, int, error) {
	if len(raw)-offset < 2 {
		return nil, 0, fmt.Errorf("truncated %s field body", name)
	}

	fieldCount, offset, err := ReadUint16(raw, offset)
	if err != nil {
		return nil, 0, err
	}
	if int(fieldCount) > limits.MaxFields {
		return nil, 0, fmt.Errorf("too many %s fields: %d > %d", name, fieldCount, limits.MaxFields)
	}
	fields := make([]Field, 0, fieldCount)
	var last uint16
	for i := 0; i < int(fieldCount); i++ {
		tag, next, err := ReadUint16(raw, offset)
		if err != nil {
			return nil, 0, err
		}
		if tag == 0 {
			return nil, 0, errors.New("wire field tag 0 is invalid")
		}
		if i > 0 && tag <= last {
			return nil, 0, errors.New("wire fields must be strictly increasing")
		}
		offset = next
		length, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, 0, err
		}
		offset = next
		if uint64(len(raw)-offset) < uint64(length) {
			return nil, 0, fmt.Errorf("truncated wire field %d", tag)
		}
		if uint64(length) > uint64(limits.MaxFieldBytes) {
			return nil, 0, fmt.Errorf("wire field %d too large: %d > %d", tag, length, limits.MaxFieldBytes)
		}
		lengthInt := int(length)
		value := make([]byte, lengthInt)
		copy(value, raw[offset:offset+lengthInt])
		fields = append(fields, Field{Tag: tag, Value: value})
		offset += lengthInt
		last = tag
	}
	return fields, offset, nil
}
