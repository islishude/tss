package wire

import (
	"fmt"
	"math"
	"reflect"
)

// ---- u32 list ---------------------------------------------------------------

func (fs fieldSchema) encodeU32List(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	n := fv.Len()
	if uint64(n) > math.MaxUint32 {
		return nil, fmt.Errorf("u32list count %d exceeds max", n)
	}
	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("u32list count %d exceeds max_items=%d", n, max)
		}
	}
	out := Uint32(uint32(n))
	for i := range n {
		elem := fv.Index(i)
		var v uint64
		if elem.Kind() == reflect.Int {
			signed := elem.Int()
			if signed < 0 || uint64(signed) > math.MaxUint32 {
				return nil, fmt.Errorf("u32list item %d value %d out of uint32 range", i, signed)
			}
			v = uint64(signed)
		} else {
			v = elem.Uint()
			if v > math.MaxUint32 {
				return nil, fmt.Errorf("u32list item %d value %d out of uint32 range", i, v)
			}
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
	if uint64(count) > uint64(maxRecordCount) {
		return fmt.Errorf("u32list count too large: %d", count)
	}
	if maxItems > 0 && uint64(count) > uint64(maxItems) {
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
	if uint64(n) > math.MaxUint32 {
		return nil, fmt.Errorf("byteslist count %d exceeds max", n)
	}
	var maxBytes int
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return nil, err
		}
		maxBytes = max
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
	out := Uint32(uint32(n))
	for i := range n {
		item := NonNilBytes(fv.Index(i).Bytes())
		if maxBytes > 0 && len(item) > maxBytes {
			return nil, fmt.Errorf("byteslist item %d length %d exceeds max_bytes=%d", i, len(item), maxBytes)
		}
		var err error
		out, err = AppendBytesChecked(out, item)
		if err != nil {
			return nil, fmt.Errorf("byteslist item %d: %w", i, err)
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
	if uint64(n) > math.MaxUint32 {
		return nil, fmt.Errorf("partybytes count %d exceeds max", n)
	}
	var maxBytes int
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return nil, err
		}
		maxBytes = max
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
	out := Uint32(uint32(n))
	for i := range n {
		rec := fv.Index(i)
		party := rec.Field(fs.partyIndex)
		bytes := rec.Field(fs.firstIndex)
		if maxBytes > 0 && bytes.Len() > maxBytes {
			return nil, fmt.Errorf("partybytes item %d bytes length %d exceeds max_bytes=%d", i, bytes.Len(), maxBytes)
		}
		out = append(out, Uint32(uint32(party.Uint()))...)
		var err error
		out, err = AppendBytesChecked(out, NonNilBytes(bytes.Bytes()))
		if err != nil {
			return nil, fmt.Errorf("partybytes item %d: %w", i, err)
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
		rec.Field(fs.partyIndex).SetUint(uint64(party))
		rec.Field(fs.firstIndex).SetBytes(value)
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
	if uint64(n) > math.MaxUint32 {
		return nil, fmt.Errorf("partybytepairs count %d exceeds max", n)
	}
	var maxBytes int
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return nil, err
		}
		maxBytes = max
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
	out := Uint32(uint32(n))
	for i := range n {
		rec := fv.Index(i)
		party := rec.Field(fs.partyIndex)
		first := rec.Field(fs.firstIndex)
		second := rec.Field(fs.secondIndex)
		if maxBytes > 0 && first.Len() > maxBytes {
			return nil, fmt.Errorf("partybytepairs item %d First length %d exceeds max_bytes=%d", i, first.Len(), maxBytes)
		}
		if maxBytes > 0 && second.Len() > maxBytes {
			return nil, fmt.Errorf("partybytepairs item %d Second length %d exceeds max_bytes=%d", i, second.Len(), maxBytes)
		}
		out = append(out, Uint32(uint32(party.Uint()))...)
		var err error
		out, err = AppendBytesChecked(out, NonNilBytes(first.Bytes()))
		if err != nil {
			return nil, fmt.Errorf("partybytepairs item %d First: %w", i, err)
		}
		out, err = AppendBytesChecked(out, NonNilBytes(second.Bytes()))
		if err != nil {
			return nil, fmt.Errorf("partybytepairs item %d Second: %w", i, err)
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
		rec.Field(fs.partyIndex).SetUint(uint64(party))
		rec.Field(fs.firstIndex).SetBytes(first)
		rec.Field(fs.secondIndex).SetBytes(second)
		out.Index(i).Set(rec)
	}
	if offset != len(raw) {
		return fmt.Errorf("trailing partybytepairs data")
	}
	fv.Set(out)
	return nil
}

// ---- custom list ------------------------------------------------------------

func (fs fieldSchema) encodeCustomList(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	n := fv.Len()
	if uint64(n) > math.MaxUint32 {
		return nil, fmt.Errorf("customlist count %d exceeds max", n)
	}
	if fs.maxItems != "" {
		max, err := fs.getLimit(fs.maxItems, limitSet)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, fmt.Errorf("customlist count %d exceeds max_items=%d", n, max)
		}
	}

	out := Uint32(uint32(n))
	for i := range n {
		elem := fv.Index(i)
		if elem.Kind() == reflect.Pointer && elem.IsNil() {
			return nil, fmt.Errorf("customlist item %d is nil", i)
		}
		m := valueMarshaler(elem)
		if m == nil {
			return nil, fmt.Errorf("customlist item %d does not implement MarshalWireValue", i)
		}
		item, err := m.MarshalWireValue()
		if err != nil {
			return nil, fmt.Errorf("customlist item %d marshal: %w", i, err)
		}
		if item == nil {
			return nil, fmt.Errorf("customlist item %d returned nil", i)
		}
		if err := fs.checkByteLimits(item, limitSet); err != nil {
			return nil, fmt.Errorf("customlist item %d: %w", i, err)
		}
		out, err = AppendBytesChecked(out, item)
		if err != nil {
			return nil, fmt.Errorf("customlist item %d: %w", i, err)
		}
	}
	return out, nil
}

func (fs fieldSchema) decodeCustomList(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
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
	if err := validateRecordCountWithLimit(raw, offset, count, 4, maxItems, "customlist"); err != nil {
		return err
	}

	elemType := fv.Type().Elem()
	out := reflect.MakeSlice(fv.Type(), int(count), int(count))
	for i := range int(count) {
		item, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
		if err != nil {
			return fmt.Errorf("customlist item %d: %w", i, err)
		}
		offset = next
		if err := fs.checkFixedLen(item); err != nil {
			return fmt.Errorf("customlist item %d: %w", i, err)
		}

		elem := reflect.New(elemType).Elem()
		target := elem
		if elemType.Kind() == reflect.Pointer {
			target = reflect.New(elemType.Elem())
		}
		u := valueUnmarshaler(target)
		if u == nil {
			return fmt.Errorf("customlist item %d does not implement UnmarshalWireValue", i)
		}
		if err := u.UnmarshalWireValue(item); err != nil {
			return fmt.Errorf("customlist item %d unmarshal: %w", i, err)
		}
		if elemType.Kind() == reflect.Pointer {
			elem.Set(target)
		} else if target.Kind() == reflect.Pointer {
			elem.Set(target.Elem())
		} else {
			elem.Set(target)
		}
		out.Index(i).Set(elem)
	}
	if offset != len(raw) {
		return fmt.Errorf("trailing customlist data")
	}
	fv.Set(out)
	return nil
}

// ---- nested -----------------------------------------------------------------

func (fs fieldSchema) encodeNested(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
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
	return Marshal(msg, WithFieldLimitsForMarshal(limitSet))
}

func (fs fieldSchema) decodeNested(fv reflect.Value, raw []byte, limitSet FieldLimits, frameLimits FrameLimits) error {
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
		if err := Unmarshal(raw, newPtr.Interface(), WithFrameLimits(frameLimits), WithFieldLimits(limitSet)); err != nil {
			return err
		}
		fv.Set(newPtr.Elem())
		return nil
	}
	return Unmarshal(raw, ptr, WithFrameLimits(frameLimits), WithFieldLimits(limitSet))
}

// ---- custom ------------------------------------------------------------------

// encodeCustom encodes a field value that implements ValueMarshaler.
// It handles nil pointer rejection, interface dispatch (value or pointer
// receiver), nil return rejection, and byte/item-limit validation.
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
	if err := fs.checkCustomItemLimit(out, limitSet); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeCustom decodes raw bytes into a field value that implements
// ValueUnmarshaler. It validates byte and declared item limits before
// auto-allocating nil pointers or invoking custom code, dispatches to the
// interface (value or pointer receiver), and requires the implementation to
// copy the input bytes.
func (fs fieldSchema) decodeCustom(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
	}
	if err := fs.checkCustomItemLimit(raw, limitSet); err != nil {
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
