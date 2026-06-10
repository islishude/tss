package wire

import (
	"fmt"
	"reflect"
)

// ---- record ------------------------------------------------------------------

// encodeRecord encodes a struct field value as a record body (field count + fields).
func (fs fieldSchema) encodeRecord(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
	return marshalRecordValue(fv, limitSet)
}

// decodeRecord decodes a record body into a struct field value.
func (fs fieldSchema) decodeRecord(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	return unmarshalRecordValue(raw, fv, limitSet)
}

// ---- record list -------------------------------------------------------------

// encodeRecordList encodes a []struct or []*struct as a length-prefixed record list.
//
// Wire format:
//
//	uint32 count
//	repeat count:
//	    uint32 record_len
//	    record bytes
func (fs fieldSchema) encodeRecordList(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
	n := fv.Len()

	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("recordlist count %d exceeds max_items=%d", n, max)
		}
	}

	// Pre-allocate: count + per-record length prefix.
	out := Uint32(uint32(n))
	for i := range n {
		elem := fv.Index(i)
		rec, err := marshalRecordValue(elem, limitSet)
		if err != nil {
			return nil, fmt.Errorf("recordlist item %d: %w", i, err)
		}
		out = append(out, Uint32(uint32(len(rec)))...)
		out = append(out, rec...)
	}
	return out, nil
}

// decodeRecordList decodes a length-prefixed record list into a slice field value.
func (fs fieldSchema) decodeRecordList(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	if len(raw) < 4 {
		return fmt.Errorf("truncated recordlist count")
	}

	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return err
	}
	if int(count) > maxRecordCount {
		return fmt.Errorf("recordlist count too large: %d > %d", count, maxRecordCount)
	}
	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return err
		}
		if int(count) > max {
			return fmt.Errorf("recordlist count %d exceeds max_items=%d", count, max)
		}
	}

	elemType := fv.Type().Elem() // T or *T
	out := reflect.MakeSlice(fv.Type(), int(count), int(count))

	for i := range int(count) {
		recLen, next, err := ReadUint32(raw, offset)
		if err != nil {
			return err
		}
		offset = next
		if uint64(len(raw)-offset) < uint64(recLen) {
			return fmt.Errorf("truncated recordlist item %d", i)
		}
		recBytes := raw[offset : offset+int(recLen)]
		offset += int(recLen)

		var elem reflect.Value
		if elemType.Kind() == reflect.Pointer {
			elem = reflect.New(elemType.Elem())
		} else {
			elem = reflect.New(elemType).Elem()
		}

		if err := unmarshalRecordValue(recBytes, elem, limitSet); err != nil {
			return fmt.Errorf("recordlist item %d: %w", i, err)
		}

		out.Index(i).Set(elem)
	}

	if offset != len(raw) {
		return fmt.Errorf("trailing recordlist data")
	}
	fv.Set(out)
	return nil
}

// ---- marshal / unmarshal record value ----------------------------------------

// marshalRecordValue encodes a struct value into the canonical record body format.
// The value may be a struct or pointer-to-struct. Nil pointers are rejected.
// When v is not addressable (e.g., a slice element from []T), an addressable copy
// is created so that pointer-receiver hooks (BeforeMarshalWire, Validate) are visible.
func marshalRecordValue(v reflect.Value, limitSet LimitSet) ([]byte, error) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, fmt.Errorf("nil record pointer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("record must be struct, got %s", v.Kind())
	}

	// Ensure v is addressable so pointer-receiver hooks are visible.
	// Slice elements from []T (not []*T) are non-addressable.
	if !v.CanAddr() {
		newV := reflect.New(v.Type())
		newV.Elem().Set(v)
		v = newV.Elem()
	}

	// BeforeMarshalWire hook.
	if bm, ok := v.Interface().(BeforeMarshaler); ok {
		if err := bm.BeforeMarshalWire(); err != nil {
			return nil, fmt.Errorf("record BeforeMarshalWire: %w", err)
		}
	} else if v.CanAddr() {
		if bm, ok := v.Addr().Interface().(BeforeMarshaler); ok {
			if err := bm.BeforeMarshalWire(); err != nil {
				return nil, fmt.Errorf("record BeforeMarshalWire: %w", err)
			}
		}
	}

	// Validate before marshal.
	if val, ok := v.Interface().(Validator); ok {
		if err := val.Validate(); err != nil {
			return nil, fmt.Errorf("record Validate: %w", err)
		}
	} else if v.CanAddr() {
		if val, ok := v.Addr().Interface().(Validator); ok {
			if err := val.Validate(); err != nil {
				return nil, fmt.Errorf("record Validate: %w", err)
			}
		}
	}

	s, err := getSchema(v.Type())
	if err != nil {
		return nil, fmt.Errorf("record %s: %w", v.Type().Name(), err)
	}

	fields := make([]Field, 0, len(s.fields))
	for i := range s.fields {
		fs2 := &s.fields[i]
		fv := v.FieldByIndex(fs2.index)
		value, err := fs2.encode(fv, limitSet)
		if err != nil {
			return nil, fmt.Errorf("record %s field %s tag %d: %w", v.Type().Name(), fs2.name, fs2.tag, err)
		}
		fields = append(fields, Field{Tag: fs2.tag, Value: value})
	}

	return marshalFieldBody(fields)
}

// unmarshalRecordValue decodes a record body into a settable struct value.
// The value must be a struct or pointer-to-struct. Nil pointers are auto-allocated.
func unmarshalRecordValue(raw []byte, dst reflect.Value, limitSet LimitSet) error {
	if dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		dst = dst.Elem()
	}
	if dst.Kind() != reflect.Struct {
		return fmt.Errorf("record must be struct, got %s", dst.Kind())
	}

	s, err := getSchema(dst.Type())
	if err != nil {
		return fmt.Errorf("record %s: %w", dst.Type().Name(), err)
	}

	limits := DefaultLimits()
	fields, offset, err := unmarshalFieldBody(raw, 0, limits, dst.Type().Name())
	if err != nil {
		return err
	}
	if offset != len(raw) {
		return fmt.Errorf("record %s: trailing bytes", dst.Type().Name())
	}

	// Exact field set: require same count and matching tag sequence.
	if len(fields) != len(s.fields) {
		return fmt.Errorf("record %s: got %d fields, want %d", dst.Type().Name(), len(fields), len(s.fields))
	}
	for i := range s.fields {
		if fields[i].Tag != s.fields[i].tag {
			return fmt.Errorf("record %s: unexpected field tag %d at index %d, want %d",
				dst.Type().Name(), fields[i].Tag, i, s.fields[i].tag)
		}
	}

	for i := range s.fields {
		fs2 := &s.fields[i]
		fv := dst.FieldByIndex(fs2.index)
		if err := fs2.decode(fv, fields[i].Value, limitSet); err != nil {
			return fmt.Errorf("record %s field %s tag %d: %w", dst.Type().Name(), fs2.name, fs2.tag, err)
		}
	}

	// AfterUnmarshalWire hook — try value, then pointer.
	if dst.CanAddr() {
		if au, ok := dst.Addr().Interface().(AfterUnmarshaler); ok {
			if err := au.AfterUnmarshalWire(); err != nil {
				return fmt.Errorf("record %s AfterUnmarshalWire: %w", dst.Type().Name(), err)
			}
		}
	} else if au, ok := dst.Interface().(AfterUnmarshaler); ok {
		if err := au.AfterUnmarshalWire(); err != nil {
			return fmt.Errorf("record %s AfterUnmarshalWire: %w", dst.Type().Name(), err)
		}
	}

	// Validate after unmarshal.
	if dst.CanAddr() {
		if val, ok := dst.Addr().Interface().(Validator); ok {
			if err := val.Validate(); err != nil {
				return fmt.Errorf("record %s Validate: %w", dst.Type().Name(), err)
			}
		}
	} else if val, ok := dst.Interface().(Validator); ok {
		if err := val.Validate(); err != nil {
			return fmt.Errorf("record %s Validate: %w", dst.Type().Name(), err)
		}
	}

	return nil
}
