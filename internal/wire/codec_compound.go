package wire

import (
	"fmt"
	"reflect"
)

// ---- u32 list ---------------------------------------------------------------

func (fs fieldSchema) encodeU32List(fv reflect.Value) ([]byte, error) {
	n := fv.Len()
	out := Uint32(uint32(n))
	for i := range n {
		elem := fv.Index(i)
		var v uint64
		if elem.Kind() == reflect.Int {
			v = uint64(elem.Int())
		} else {
			v = elem.Uint()
		}
		out = append(out, Uint32(uint32(v))...)
	}
	return out, nil
}

func (fs fieldSchema) decodeU32List(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
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
	if int(count) > maxRecordCount {
		return fmt.Errorf("u32list count too large: %d", count)
	}
	if maxItems > 0 && int(count) > maxItems {
		return fmt.Errorf("u32list count %d exceeds max_items=%d", count, maxItems)
	}
	if uint64(len(raw)-offset) != uint64(count)*4 {
		return fmt.Errorf("invalid u32list length")
	}
	elemType := fv.Type().Elem()
	isInt := elemType.Kind() == reflect.Int
	out := reflect.MakeSlice(fv.Type(), int(count), int(count))
	for i := range int(count) {
		v, next, err := ReadUint32(raw, offset)
		if err != nil {
			return err
		}
		offset = next
		elem := reflect.New(elemType).Elem()
		if isInt {
			elem.SetInt(int64(v))
		} else {
			elem.SetUint(uint64(v))
		}
		out.Index(i).Set(elem)
	}
	fv.Set(out)
	return nil
}

// ---- bytes list -------------------------------------------------------------

func (fs fieldSchema) encodeBytesList(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	n := fv.Len()
	out := Uint32(uint32(n))
	for i := range n {
		out = AppendBytes(out, NonNilBytes(fv.Index(i).Bytes()))
	}
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return nil, err
		}
		for i := range n {
			if fv.Index(i).Len() > max {
				return nil, fmt.Errorf("byteslist item %d length %d exceeds max_bytes=%d", i, fv.Index(i).Len(), max)
			}
		}
	}
	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("byteslist count %d exceeds max_items=%d", n, max)
		}
	}
	return out, nil
}

func (fs fieldSchema) decodeBytesList(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
	var maxItems, maxItemBytes int
	if fs.maxItems != "" {
		v, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return err
		}
		maxItems = v
	}
	if fs.maxBytes != "" {
		v, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return err
		}
		maxItemBytes = v
	}

	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 4, maxItems, "byteslist"); err != nil {
		return err
	}

	elemType := fv.Type().Elem()
	out := reflect.MakeSlice(fv.Type(), int(count), int(count))
	for i := range int(count) {
		item, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
		if err != nil {
			return err
		}
		offset = next
		elem := reflect.New(elemType).Elem()
		elem.SetBytes(item)
		out.Index(i).Set(elem)
	}
	if offset != len(raw) {
		return fmt.Errorf("trailing byteslist data")
	}
	fv.Set(out)
	return nil
}

// ---- party bytes ------------------------------------------------------------

func (fs fieldSchema) encodePartyBytes(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	n := fv.Len()
	out := Uint32(uint32(n))
	for i := range n {
		rec := fv.Index(i)
		party := rec.Field(0)
		bytes := rec.Field(1)
		out = append(out, Uint32(uint32(party.Uint()))...)
		out = AppendBytes(out, NonNilBytes(bytes.Bytes()))
	}
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return nil, err
		}
		for i := range n {
			b := fv.Index(i).Field(1)
			if b.Len() > max {
				return nil, fmt.Errorf("partybytes item %d bytes length %d exceeds max_bytes=%d", i, b.Len(), max)
			}
		}
	}
	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("partybytes count %d exceeds max_items=%d", n, max)
		}
	}
	return out, nil
}

func (fs fieldSchema) decodePartyBytes(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
	var maxItems, maxItemBytes int
	if fs.maxItems != "" {
		v, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return err
		}
		maxItems = v
	}
	if fs.maxBytes != "" {
		v, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return err
		}
		maxItemBytes = v
	}

	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 8, maxItems, "partybytes"); err != nil {
		return err
	}

	elemType := fv.Type().Elem() // PartyBytes[T]
	out := reflect.MakeSlice(fv.Type(), int(count), int(count))
	for i := range int(count) {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return err
		}
		offset = next
		value, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
		if err != nil {
			return err
		}
		offset = next

		rec := reflect.New(elemType).Elem()
		rec.Field(0).SetUint(uint64(party))
		rec.Field(1).SetBytes(value)
		out.Index(i).Set(rec)
	}
	if offset != len(raw) {
		return fmt.Errorf("trailing partybytes data")
	}
	fv.Set(out)
	return nil
}

// ---- party byte pairs -------------------------------------------------------

func (fs fieldSchema) encodePartyBytePairs(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	n := fv.Len()
	out := Uint32(uint32(n))
	for i := range n {
		rec := fv.Index(i)
		party := rec.Field(0)
		first := rec.Field(1)
		second := rec.Field(2)
		out = append(out, Uint32(uint32(party.Uint()))...)
		out = AppendBytes(out, NonNilBytes(first.Bytes()))
		out = AppendBytes(out, NonNilBytes(second.Bytes()))
	}
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return nil, err
		}
		for i := range n {
			f := fv.Index(i).Field(1)
			s := fv.Index(i).Field(2)
			if f.Len() > max {
				return nil, fmt.Errorf("partybytepairs item %d First length %d exceeds max_bytes=%d", i, f.Len(), max)
			}
			if s.Len() > max {
				return nil, fmt.Errorf("partybytepairs item %d Second length %d exceeds max_bytes=%d", i, s.Len(), max)
			}
		}
	}
	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("partybytepairs count %d exceeds max_items=%d", n, max)
		}
	}
	return out, nil
}

func (fs fieldSchema) decodePartyBytePairs(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
	var maxItems, maxItemBytes int
	if fs.maxItems != "" {
		v, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return err
		}
		maxItems = v
	}
	if fs.maxBytes != "" {
		v, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return err
		}
		maxItemBytes = v
	}

	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 12, maxItems, "partybytepairs"); err != nil {
		return err
	}

	elemType := fv.Type().Elem() // PartyBytePair[T]
	out := reflect.MakeSlice(fv.Type(), int(count), int(count))
	for i := range int(count) {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return err
		}
		offset = next
		first, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
		if err != nil {
			return err
		}
		offset = next
		second, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
		if err != nil {
			return err
		}
		offset = next

		rec := reflect.New(elemType).Elem()
		rec.Field(0).SetUint(uint64(party))
		rec.Field(1).SetBytes(first)
		rec.Field(2).SetBytes(second)
		out.Index(i).Set(rec)
	}
	if offset != len(raw) {
		return fmt.Errorf("trailing partybytepairs data")
	}
	fv.Set(out)
	return nil
}

// ---- nested -----------------------------------------------------------------

func (fs fieldSchema) encodeNested(fv reflect.Value) ([]byte, error) {
	// If the field is a pointer, dereference it.
	var msg Message
	if fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			return nil, fmt.Errorf("nested pointer is nil")
		}
		msg = fv.Interface().(Message)
	} else if fv.CanAddr() {
		msg = fv.Addr().Interface().(Message)
	} else {
		msg = fv.Interface().(Message)
	}
	return Marshal(msg)
}

func (fs fieldSchema) decodeNested(fv reflect.Value, raw []byte) error {
	// Ensure we have a non-nil pointer to unmarshal into.
	var ptr any
	if fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		ptr = fv.Interface()
	} else if fv.CanAddr() {
		ptr = fv.Addr().Interface()
	} else {
		// Create a new value and unmarshal, then set.
		newPtr := reflect.New(fv.Type())
		if err := Unmarshal(raw, newPtr.Interface()); err != nil {
			return err
		}
		fv.Set(newPtr.Elem())
		return nil
	}
	return Unmarshal(raw, ptr)
}

// ---- custom ------------------------------------------------------------------

// encodeCustom encodes a field value that implements ValueMarshaler.
// It handles nil pointer rejection, interface dispatch (value or pointer
// receiver), nil return rejection, and byte-limit validation.
func (fs fieldSchema) encodeCustom(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	if fv.Kind() == reflect.Pointer && fv.IsNil() {
		return nil, fmt.Errorf("wire: nil custom field %s", fs.name)
	}

	m := valueMarshaler(fv)
	if m == nil {
		return nil, fmt.Errorf("wire: field %s does not implement MarshalWireValue", fs.name)
	}

	out, err := m.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("wire: field %s tag %d custom marshal: %w", fs.name, fs.tag, err)
	}
	if out == nil {
		return nil, fmt.Errorf("wire: custom field %s returned nil", fs.name)
	}

	if err := fs.checkByteLimits(out, limitSet); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeCustom decodes raw bytes into a field value that implements
// ValueUnmarshaler. It validates byte limits first, auto-allocates nil
// pointers, dispatches to the interface (value or pointer receiver), and
// requires the implementation to copy the input bytes.
func (fs fieldSchema) decodeCustom(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
	}

	if fv.Kind() == reflect.Pointer && fv.IsNil() {
		fv.Set(reflect.New(fv.Type().Elem()))
	}

	u := valueUnmarshaler(fv)
	if u == nil {
		return fmt.Errorf("wire: field %s does not implement UnmarshalWireValue", fs.name)
	}

	if err := u.UnmarshalWireValue(raw); err != nil {
		return fmt.Errorf("wire: field %s tag %d custom unmarshal: %w", fs.name, fs.tag, err)
	}
	return nil
}

// valueMarshaler returns the ValueMarshaler implemented by v, trying the
// value first and then the addressable pointer (for pointer-receiver methods).
func valueMarshaler(v reflect.Value) ValueMarshaler {
	if m, ok := v.Interface().(ValueMarshaler); ok {
		return m
	}
	if v.CanAddr() {
		if m, ok := v.Addr().Interface().(ValueMarshaler); ok {
			return m
		}
	}
	return nil
}

// valueUnmarshaler returns the ValueUnmarshaler implemented by v, trying the
// value first and then the addressable pointer (for pointer-receiver methods).
func valueUnmarshaler(v reflect.Value) ValueUnmarshaler {
	if u, ok := v.Interface().(ValueUnmarshaler); ok {
		return u
	}
	if v.CanAddr() {
		if u, ok := v.Addr().Interface().(ValueUnmarshaler); ok {
			return u
		}
	}
	return nil
}
