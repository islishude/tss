package wire

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
)

// ---- map encode -------------------------------------------------------------

// encodeMap encodes a map[uint32-compatible]V field into canonical wire bytes.
//
// Wire format:
//
//	uint32 entry_count
//	repeat entry_count:
//	    uint32 key_len   (always 4)
//	    key_bytes        (big-endian uint32)
//	    uint32 value_len
//	    value_bytes
//
// Entries are sorted by key_bytes in ascending lexicographic order.
// Duplicate keys are rejected.
func (fs fieldSchema) encodeMap(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	if fv.IsNil() {
		return Uint32(0), nil
	}

	n := fv.Len()

	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("map count %d exceeds max_items=%d", n, max)
		}
	}

	type mapEntry struct {
		key   []byte
		value []byte
	}

	entries := make([]mapEntry, 0, n)

	for _, k := range fv.MapKeys() {
		keyBytes, err := fs.encodeMapKey(k)
		if err != nil {
			return nil, err
		}

		valueBytes, err := fs.encodeMapValue(fv.MapIndex(k), limitSet)
		if err != nil {
			return nil, err
		}

		entries = append(entries, mapEntry{
			key:   keyBytes,
			value: valueBytes,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].key, entries[j].key) < 0
	})

	out := Uint32(uint32(len(entries)))

	for i, entry := range entries {
		if i > 0 && bytes.Compare(entries[i-1].key, entry.key) >= 0 {
			return nil, fmt.Errorf("map entries contain duplicate canonical key")
		}
		out = AppendBytes(out, entry.key)
		out = AppendBytes(out, entry.value)
	}

	return out, nil
}

// ---- map decode -------------------------------------------------------------

// decodeMap decodes a canonical map field value into a Go map.
//
// Decoding enforces:
//   - count within limits (maxItems, maxRecordCount)
//   - exact 4-byte keys
//   - strict ascending sort order
//   - no duplicate keys
//   - no trailing bytes
func (fs fieldSchema) decodeMap(
	fv reflect.Value,
	raw []byte,
	limitSet FieldLimits,
	frameLimits FrameLimits,
) error {
	var maxItems int
	if fs.maxItems != "" {
		v, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return err
		}
		maxItems = v
	}

	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return err
	}

	if err := validateRecordCountWithLimit(raw, offset, count, 12, maxItems, "map"); err != nil {
		return err
	}

	out := reflect.MakeMapWithSize(fv.Type(), int(count))

	var prevKey []byte

	for i := 0; i < int(count); i++ {
		keyBytes, next, err := ReadBytesWithLimit(raw, offset, 4)
		if err != nil {
			return err
		}
		offset = next

		if len(keyBytes) != 4 {
			return fmt.Errorf("map key %d length %d, want 4", i, len(keyBytes))
		}

		if i > 0 && bytes.Compare(prevKey, keyBytes) >= 0 {
			return fmt.Errorf("map entries not strictly sorted at index %d", i)
		}
		prevKey = keyBytes

		valueBytes, next, err := ReadBytes(raw, offset)
		if err != nil {
			return err
		}
		offset = next

		key, err := fs.decodeMapKey(keyBytes)
		if err != nil {
			return err
		}

		value, err := fs.decodeMapValue(valueBytes, limitSet, frameLimits)
		if err != nil {
			return err
		}

		if out.MapIndex(key).IsValid() {
			return fmt.Errorf("map duplicate key at index %d", i)
		}
		out.SetMapIndex(key, value)
	}

	if offset != len(raw) {
		return fmt.Errorf("trailing map data")
	}

	fv.Set(out)
	return nil
}

// ---- map key codec ----------------------------------------------------------

// encodeMapKey encodes a uint32-compatible map key into wire key bytes.
func (fs fieldSchema) encodeMapKey(k reflect.Value) ([]byte, error) {
	if k.Kind() != reflect.Uint32 {
		return nil, fmt.Errorf("map key must be uint32-compatible, got %s", k.Type())
	}
	return Uint32(uint32(k.Uint())), nil
}

// decodeMapKey decodes wire key bytes into a reflect.Value of the map key type.
func (fs fieldSchema) decodeMapKey(raw []byte) (reflect.Value, error) {
	v, err := DecodeUint32(raw)
	if err != nil {
		return reflect.Value{}, err
	}

	key := reflect.New(fs.mapKeyType).Elem()
	key.SetUint(uint64(v))
	return key, nil
}

// ---- map value codec --------------------------------------------------------

// encodeMapValue encodes a map value using its inferred wire kind.
func (fs fieldSchema) encodeMapValue(v reflect.Value, limitSet FieldLimits) ([]byte, error) {
	valueFS := fieldSchema{
		tag:      fs.tag,
		name:     fs.name + " value",
		kind:     fs.mapValueKind,
		typ:      fs.mapValueType,
		fixedLen: fs.fixedLen,
		maxBytes: fs.maxBytes,
		maxBits:  fs.maxBits,
	}
	return valueFS.encode(v, limitSet)
}

// decodeMapValue decodes a map value using its inferred wire kind.
func (fs fieldSchema) decodeMapValue(
	raw []byte,
	limitSet FieldLimits,
	frameLimits FrameLimits,
) (reflect.Value, error) {
	value := reflect.New(fs.mapValueType).Elem()

	valueFS := fieldSchema{
		tag:      fs.tag,
		name:     fs.name + " value",
		kind:     fs.mapValueKind,
		typ:      fs.mapValueType,
		fixedLen: fs.fixedLen,
		maxBytes: fs.maxBytes,
		maxBits:  fs.maxBits,
	}

	if err := valueFS.decode(value, raw, limitSet, frameLimits); err != nil {
		return reflect.Value{}, err
	}

	return value, nil
}
