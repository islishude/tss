package wire

import (
	"errors"
	"fmt"
	"math/big"
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
	case kindCustom:
		return fs.encodeCustom(fv, limitSet)
	case kindBigInt:
		return fs.encodeBigIntDispatch(fv, limitSet)
	case kindBigUint:
		return fs.encodeBigUintDispatch(fv, limitSet)
	case kindBigPos:
		return fs.encodeBigPosDispatch(fv, limitSet)
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
	case kindCustom:
		return fs.decodeCustom(fv, raw, limitSet)
	case kindBigInt:
		return fs.decodeBigIntDispatch(fv, raw, limitSet)
	case kindBigUint:
		return fs.decodeBigUintDispatch(fv, raw, limitSet)
	case kindBigPos:
		return fs.decodeBigPosDispatch(fv, raw, limitSet)
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
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
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

// ---- byte limit checks -------------------------------------------------------

// checkByteLimits validates raw bytes against len=N, max_bytes=N, and
// max_bytes=name options. It is used by both bytes and custom field kinds.
func (fs fieldSchema) checkByteLimits(raw []byte, limitSet LimitSet) error {
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

// ---- custom ------------------------------------------------------------------

// encodeCustom encodes a field value that implements ValueMarshaler.
// It handles nil pointer rejection, interface dispatch (value or pointer
// receiver), nil return rejection, and byte-limit validation.
func (fs fieldSchema) encodeCustom(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
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
func (fs fieldSchema) decodeCustom(fv reflect.Value, raw []byte, limitSet LimitSet) error {
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

// ---- big integer -------------------------------------------------------------

// bigIntFromValue extracts a *big.Int from a reflect.Value that may be
// a value (big.Int) or pointer (*big.Int). Returns nil for nil pointers.
func bigIntFromValue(v reflect.Value) *big.Int {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return v.Interface().(*big.Int)
	}
	x := v.Interface().(big.Int)
	return new(big.Int).Set(&x)
}

// setBigIntValue sets a reflect.Value from a *big.Int. Handles both
// value (big.Int) and pointer (*big.Int) field types.
func setBigIntValue(v reflect.Value, x *big.Int) {
	if v.Kind() == reflect.Pointer {
		v.Set(reflect.ValueOf(x))
	} else {
		v.Set(reflect.ValueOf(*x))
	}
}

// encodeBigIntSigned encodes x using canonical signed-magnitude format.
// Zero is encoded as [0x00]. Nil is treated as zero.
func encodeBigIntSigned(x *big.Int) ([]byte, error) {
	if x == nil {
		return []byte{0x00}, nil
	}
	switch x.Sign() {
	case 0:
		return []byte{0x00}, nil
	case -1:
		// big.Int.Bytes() returns the absolute value — no need for Abs() here.
		return append([]byte{0x01}, x.Bytes()...), nil
	default:
		return append([]byte{0x00}, x.Bytes()...), nil
	}
}

// decodeBigIntSigned decodes a canonical signed-magnitude encoding.
// Rejects empty input, invalid sign bytes, negative zero, and
// leading-zero magnitudes.
func decodeBigIntSigned(b []byte) (*big.Int, error) {
	if len(b) == 0 {
		return nil, errors.New("signed integer: empty encoding")
	}
	sign := b[0]
	if sign != 0x00 && sign != 0x01 {
		return nil, fmt.Errorf("signed integer: invalid sign byte 0x%02x", sign)
	}
	mag := b[1:]
	if len(mag) == 0 {
		if sign == 0x00 {
			return new(big.Int), nil
		}
		return nil, errors.New("signed integer: negative zero is invalid")
	}
	if mag[0] == 0 {
		return nil, errors.New("signed integer: non-minimal magnitude (leading zero)")
	}
	val := new(big.Int).SetBytes(mag)
	if sign == 0x01 {
		val.Neg(val)
	}
	return val, nil
}

// encodeBigUint encodes x as minimal big-endian magnitude.
// Zero and nil are encoded as empty.
func encodeBigUint(x *big.Int) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if x.Sign() < 0 {
		return nil, errors.New("unsigned integer: negative value")
	}
	if x.Sign() == 0 {
		return []byte{}, nil
	}
	return x.Bytes(), nil
}

// decodeBigUint decodes a minimal big-endian unsigned integer.
// Empty encoding represents zero. Rejects leading-zero encodings.
func decodeBigUint(b []byte) (*big.Int, error) {
	if len(b) == 0 {
		return new(big.Int), nil
	}
	if b[0] == 0 {
		return nil, errors.New("unsigned integer: non-minimal encoding")
	}
	return new(big.Int).SetBytes(b), nil
}

// encodeBigPos encodes x as minimal big-endian magnitude.
// Rejects nil, zero, and negative values.
func encodeBigPos(x *big.Int) ([]byte, error) {
	if x == nil {
		return nil, errors.New("positive integer: nil value")
	}
	if x.Sign() <= 0 {
		return nil, errors.New("positive integer: must be > 0")
	}
	return x.Bytes(), nil
}

// decodeBigPos decodes a minimal big-endian positive integer.
// Rejects empty input, zero, leading-zero encodings, and negative values.
func decodeBigPos(b []byte) (*big.Int, error) {
	if len(b) == 0 {
		return nil, errors.New("positive integer: empty encoding")
	}
	if b[0] == 0 {
		return nil, errors.New("positive integer: non-minimal encoding")
	}
	x := new(big.Int).SetBytes(b)
	if x.Sign() <= 0 {
		return nil, errors.New("positive integer: value must be positive")
	}
	return x, nil
}

// ---- exported big integer helpers ---------------------------------------------

// These functions are the canonical signed/unsigned/positive integer encoders
// used by both the wire codec (via the tag-driven dispatch) and protocol code
// that needs deterministic byte encoding for transcript binding, hashing, and
// evidence construction. They match the encoding rules of the corresponding
// wire kinds: bigint / biguint / bigpos.

// EncodeBigInt encodes x using canonical signed-magnitude format (bigint kind).
// Zero is encoded as [0x00], nil as zero.
func EncodeBigInt(x *big.Int) ([]byte, error) { return encodeBigIntSigned(x) }

// DecodeBigInt decodes a canonical signed-magnitude encoding (bigint kind).
func DecodeBigInt(in []byte) (*big.Int, error) { return decodeBigIntSigned(in) }

// EncodeBigUint encodes x as minimal big-endian magnitude (biguint kind).
// Zero and nil are encoded as empty.
func EncodeBigUint(x *big.Int) ([]byte, error) { return encodeBigUint(x) }

// DecodeBigUint decodes a minimal big-endian unsigned integer (biguint kind).
func DecodeBigUint(in []byte) (*big.Int, error) { return decodeBigUint(in) }

// EncodeBigPos encodes x as minimal big-endian magnitude (bigpos kind).
// Rejects nil, zero, and negative values.
func EncodeBigPos(x *big.Int) ([]byte, error) { return encodeBigPos(x) }

// DecodeBigPos decodes a minimal big-endian positive integer (bigpos kind).
func DecodeBigPos(in []byte) (*big.Int, error) { return decodeBigPos(in) }

// ---- big integer dispatch ----------------------------------------------------

// encodeBigIntDispatch encodes a field value as a canonical signed integer.
func (fs fieldSchema) encodeBigIntDispatch(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
	x := bigIntFromValue(fv)
	out, err := encodeBigIntSigned(x)
	if err != nil {
		return nil, fmt.Errorf("wire: field %s tag %d bigint marshal: %w", fs.name, fs.tag, err)
	}
	if err := fs.checkByteLimits(out, limitSet); err != nil {
		return nil, err
	}
	return out, nil
}

// encodeBigUintDispatch encodes a field value as a canonical unsigned integer.
func (fs fieldSchema) encodeBigUintDispatch(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
	x := bigIntFromValue(fv)
	out, err := encodeBigUint(x)
	if err != nil {
		return nil, fmt.Errorf("wire: field %s tag %d biguint marshal: %w", fs.name, fs.tag, err)
	}
	if err := fs.checkByteLimits(out, limitSet); err != nil {
		return nil, err
	}
	return out, nil
}

// encodeBigPosDispatch encodes a field value as a canonical positive integer.
func (fs fieldSchema) encodeBigPosDispatch(fv reflect.Value, limitSet LimitSet) ([]byte, error) {
	x := bigIntFromValue(fv)
	out, err := encodeBigPos(x)
	if err != nil {
		return nil, fmt.Errorf("wire: field %s tag %d bigpos marshal: %w", fs.name, fs.tag, err)
	}
	if err := fs.checkByteLimits(out, limitSet); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeBigIntDispatch decodes raw bytes into a signed integer field.
func (fs fieldSchema) decodeBigIntDispatch(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
	}
	if fv.Kind() == reflect.Pointer && fv.IsNil() {
		fv.Set(reflect.New(fv.Type().Elem()))
	}
	x, err := decodeBigIntSigned(raw)
	if err != nil {
		return fmt.Errorf("wire: field %s tag %d bigint unmarshal: %w", fs.name, fs.tag, err)
	}
	setBigIntValue(fv, x)
	return nil
}

// decodeBigUintDispatch decodes raw bytes into an unsigned integer field.
func (fs fieldSchema) decodeBigUintDispatch(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
	}
	if fv.Kind() == reflect.Pointer && fv.IsNil() {
		fv.Set(reflect.New(fv.Type().Elem()))
	}
	x, err := decodeBigUint(raw)
	if err != nil {
		return fmt.Errorf("wire: field %s tag %d biguint unmarshal: %w", fs.name, fs.tag, err)
	}
	setBigIntValue(fv, x)
	return nil
}

// decodeBigPosDispatch decodes raw bytes into a positive integer field.
func (fs fieldSchema) decodeBigPosDispatch(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
	}
	if fv.Kind() == reflect.Pointer && fv.IsNil() {
		fv.Set(reflect.New(fv.Type().Elem()))
	}
	x, err := decodeBigPos(raw)
	if err != nil {
		return fmt.Errorf("wire: field %s tag %d bigpos unmarshal: %w", fs.name, fs.tag, err)
	}
	setBigIntValue(fv, x)
	return nil
}
