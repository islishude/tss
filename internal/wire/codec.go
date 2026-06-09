package wire

import (
	"fmt"
	"reflect"
	"unicode/utf8"
)

// ---- encode dispatch ---------------------------------------------------------

// encode serialises the field value fv into its canonical wire bytes.
func (fs fieldSchema) encode(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
	switch fs.kind {
	case kindU8:
		return []byte{byte(fv.Uint())}, nil
	case kindU16:
		return Uint16(uint16(fv.Uint())), nil
	case kindU32:
		v := fs.uintValue(fv)
		if v > maxUint32 {
			return nil, fmt.Errorf("uint32 value %d exceeds max", v)
		}
		return Uint32(uint32(v)), nil
	case kindBool:
		return Bool(fv.Bool()), nil
	case kindBytes:
		return fs.encodeBytes(fv), nil
	case kindString:
		s := fv.String()
		if !utf8.ValidString(s) {
			return nil, fmt.Errorf("string is not valid UTF-8")
		}
		return []byte(s), nil
	case kindU32List:
		return fs.encodeU32List(fv)
	case kindBytesList:
		return fs.encodeBytesList(fv, limitSet)
	case kindPartyBytes:
		return fs.encodePartyBytes(fv, limitSet)
	case kindPartyBytePairs:
		return fs.encodePartyBytePairs(fv, limitSet)
	case kindNested:
		return fs.encodeNested(fv)
	default:
		return nil, fmt.Errorf("unsupported wire kind %d", fs.kind)
	}
}

// ---- decode dispatch ---------------------------------------------------------

// decode deserialises raw into the settable field value fv.
func (fs fieldSchema) decode(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	switch fs.kind {
	case kindU8:
		return fs.decodeU8(fv, raw)
	case kindU16:
		return fs.decodeU16(fv, raw)
	case kindU32:
		return fs.decodeU32(fv, raw)
	case kindBool:
		return fs.decodeBool(fv, raw)
	case kindBytes:
		return fs.decodeBytes(fv, raw, limitSet)
	case kindString:
		return fs.decodeString(fv, raw)
	case kindU32List:
		return fs.decodeU32List(fv, raw, limitSet)
	case kindBytesList:
		return fs.decodeBytesList(fv, raw, limitSet)
	case kindPartyBytes:
		return fs.decodePartyBytes(fv, raw, limitSet)
	case kindPartyBytePairs:
		return fs.decodePartyBytePairs(fv, raw, limitSet)
	case kindNested:
		return fs.decodeNested(fv, raw)
	default:
		return fmt.Errorf("unsupported wire kind %d", fs.kind)
	}
}

// ---- helpers ----------------------------------------------------------------

const maxUint32 = (1 << 32) - 1

const maxNoLimit = 1<<31 - 1 // sentinel returned when no LimitSet is provided

// getLimit returns the limit value for name.
// When limitSet is nil, no limit is enforced and maxNoLimit is returned.
// When limitSet is non-nil but name is missing, an error is returned.
func (fs fieldSchema) getLimit(name string, limitSet LimitSet) (int, error) {
	if limitSet == nil {
		return maxNoLimit, nil
	}
	v, ok := limitSet[name]
	if !ok {
		return 0, fmt.Errorf("limit %q is required but not provided", name)
	}
	return v, nil
}

// ---- simple decoders --------------------------------------------------------

func (fs fieldSchema) decodeU8(fv reflect.Value, raw []byte) error {
	if len(raw) != 1 {
		return fmt.Errorf("u8: got %d bytes, want 1", len(raw))
	}
	fv.SetUint(uint64(raw[0]))
	return nil
}

func (fs fieldSchema) decodeU16(fv reflect.Value, raw []byte) error {
	v, err := DecodeUint16(raw)
	if err != nil {
		return err
	}
	fv.SetUint(uint64(v))
	return nil
}

func (fs fieldSchema) decodeU32(fv reflect.Value, raw []byte) error {
	v, err := DecodeUint32(raw)
	if err != nil {
		return err
	}
	fs.setUintValue(fv, uint64(v))
	return nil
}

// uintValue returns the unsigned value of a uint32-compatible field (uint32 or int).
func (fs fieldSchema) uintValue(fv reflect.Value) uint64 {
	if fv.Kind() == reflect.Int {
		return uint64(fv.Int())
	}
	return fv.Uint()
}

// setUintValue sets a uint32-compatible field from an unsigned value.
func (fs fieldSchema) setUintValue(fv reflect.Value, v uint64) {
	if fv.Kind() == reflect.Int {
		fv.SetInt(int64(v))
	} else {
		fv.SetUint(v)
	}
}

// encodeBytes returns the canonical wire bytes for a []byte or [N]byte field.
func (fs fieldSchema) encodeBytes(fv reflect.Value) []byte {
	if fv.Kind() == reflect.Array {
		n := fv.Len()
		out := make([]byte, n)
		for i := range n {
			out[i] = byte(fv.Index(i).Uint())
		}
		return NonNilBytes(out)
	}
	return NonNilBytes(fv.Bytes())
}

// setBytesValue sets a []byte or [N]byte field from raw bytes.
func (fs fieldSchema) setBytesValue(fv reflect.Value, out []byte) {
	if fv.Kind() == reflect.Array {
		n := fv.Len()
		for i := range min(n, len(out)) {
			fv.Index(i).SetUint(uint64(out[i]))
		}
	} else {
		fv.SetBytes(out)
	}
}

func (fs fieldSchema) decodeBool(fv reflect.Value, raw []byte) error {
	v, err := DecodeBool(raw)
	if err != nil {
		return err
	}
	fv.SetBool(v)
	return nil
}

func (fs fieldSchema) decodeBytes(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	if err := fs.checkFixedLen(raw); err != nil {
		return err
	}
	if fs.maxBytes != "" {
		max, err := fs.getLimit(fs.maxBytes, limitSet)
		if err != nil {
			return err
		}
		if len(raw) > max {
			return fmt.Errorf("bytes length %d exceeds max_bytes=%d", len(raw), max)
		}
	}
	// Copy to prevent aliasing with the decode buffer.
	out := make([]byte, len(raw))
	copy(out, raw)
	fs.setBytesValue(fv, out)
	return nil
}

func (fs fieldSchema) decodeString(fv reflect.Value, raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("string is not valid UTF-8")
	}
	fv.SetString(string(raw))
	return nil
}

// ---- fixed length checker ----------------------------------------------------

func (fs fieldSchema) checkFixedLen(raw []byte) error {
	if fs.fixedLen > 0 && len(raw) != fs.fixedLen {
		return fmt.Errorf("got %d bytes, want %d", len(raw), fs.fixedLen)
	}
	return nil
}

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

func (fs fieldSchema) decodeU32List(fv reflect.Value, raw []byte, limitSet LimitSet) error {
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

func (fs fieldSchema) encodeBytesList(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
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

func (fs fieldSchema) decodeBytesList(fv reflect.Value, raw []byte, limitSet LimitSet) error {
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

func (fs fieldSchema) encodePartyBytes(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
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

func (fs fieldSchema) decodePartyBytes(fv reflect.Value, raw []byte, limitSet LimitSet) error {
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

func (fs fieldSchema) encodePartyBytePairs(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
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

func (fs fieldSchema) decodePartyBytePairs(fv reflect.Value, raw []byte, limitSet LimitSet) error {
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
