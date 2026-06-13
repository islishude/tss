package wire

import (
	"fmt"
	"math"
	"reflect"
	"unicode/utf8"
)

// ---- encode dispatch ---------------------------------------------------------

// encode serialises the field value fv into its canonical wire bytes.
func (fs fieldSchema) encode(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	switch fs.kind {
	case kindU8:
		return []byte{byte(fv.Uint())}, nil
	case kindU16:
		return Uint16(uint16(fv.Uint())), nil
	case kindU32:
		v := fs.uintValue(fv)
		if v > math.MaxUint32 {
			return nil, fmt.Errorf("uint32 value %d exceeds max", v)
		}
		return Uint32(uint32(v)), nil
	case kindBool:
		return Bool(fv.Bool()), nil
	case kindBytes:
		raw := fs.encodeBytes(fv)
		if err := fs.checkByteLimits(raw, limitSet); err != nil {
			return nil, err
		}
		if err := fs.checkBitsLimit(len(raw)*8, limitSet); err != nil {
			return nil, err
		}
		return raw, nil
	case kindString:
		s := fv.String()
		if !utf8.ValidString(s) {
			return nil, fmt.Errorf("string is not valid UTF-8")
		}
		raw := []byte(s)
		if err := fs.checkByteLimits(raw, limitSet); err != nil {
			return nil, err
		}
		return raw, nil
	case kindU32List:
		return fs.encodeU32List(fv, limitSet)
	case kindBytesList:
		return fs.encodeBytesList(fv, limitSet)
	case kindPartyBytes:
		return fs.encodePartyBytes(fv, limitSet)
	case kindPartyBytePairs:
		return fs.encodePartyBytePairs(fv, limitSet)
	case kindNested:
		return fs.encodeNested(fv, limitSet)
	case kindCustom:
		return fs.encodeCustom(fv, limitSet)
	case kindBigInt:
		return fs.encodeBigIntDispatch(fv, limitSet)
	case kindBigUint:
		return fs.encodeBigUintDispatch(fv, limitSet)
	case kindBigPos:
		return fs.encodeBigPosDispatch(fv, limitSet)
	case kindRecord:
		return fs.encodeRecord(fv, limitSet)
	case kindRecordList:
		return fs.encodeRecordList(fv, limitSet)
	default:
		return nil, fmt.Errorf("unsupported wire kind %d", fs.kind)
	}
}

// ---- decode dispatch ---------------------------------------------------------

// decode deserialises raw into the settable field value fv.
func (fs fieldSchema) decode(fv reflect.Value, raw []byte, limitSet FieldLimits, frameLimits FrameLimits) error {
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
		return fs.decodeString(fv, raw, limitSet)
	case kindU32List:
		return fs.decodeU32List(fv, raw, limitSet)
	case kindBytesList:
		return fs.decodeBytesList(fv, raw, limitSet)
	case kindPartyBytes:
		return fs.decodePartyBytes(fv, raw, limitSet)
	case kindPartyBytePairs:
		return fs.decodePartyBytePairs(fv, raw, limitSet)
	case kindNested:
		return fs.decodeNested(fv, raw, limitSet, frameLimits)
	case kindCustom:
		return fs.decodeCustom(fv, raw, limitSet)
	case kindBigInt:
		return fs.decodeBigIntDispatch(fv, raw, limitSet)
	case kindBigUint:
		return fs.decodeBigUintDispatch(fv, raw, limitSet)
	case kindBigPos:
		return fs.decodeBigPosDispatch(fv, raw, limitSet)
	case kindRecord:
		return fs.decodeRecord(fv, raw, limitSet, frameLimits)
	case kindRecordList:
		return fs.decodeRecordList(fv, raw, limitSet, frameLimits)
	default:
		return fmt.Errorf("unsupported wire kind %d", fs.kind)
	}
}

// ---- helpers ----------------------------------------------------------------

// getLimit returns the limit value for name from the provided FieldLimits.
// Fail-closed: when limitSet is nil or name is missing, an error is returned.
// Every wire tag that declares max_bytes=name or max_items=name requires the
// caller to provide a FieldLimits containing that name.
func (fs fieldSchema) getLimit(name string, limitSet FieldLimits) (int, error) {
	if limitSet == nil {
		return 0, fmt.Errorf("wire: missing field limit %q for field %q", name, fs.name)
	}
	v, ok := limitSet[name]
	if !ok {
		return 0, fmt.Errorf("wire: missing field limit %q for field %q", name, fs.name)
	}
	if v <= 0 {
		return 0, fmt.Errorf("wire: field limit %q for field %q must be positive", name, fs.name)
	}
	return v, nil
}

// ---- byte limit checks -------------------------------------------------------

// checkByteLimits validates raw bytes against len=N, max_bytes=N, and
// max_bytes=name options. It is used by both bytes and custom field kinds.
func (fs fieldSchema) checkByteLimits(raw []byte, limitSet FieldLimits) error {
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

// ---- bit limit checks ---------------------------------------------------------

// checkBitsLimit validates the bit length of a decoded big integer or the
// approximated bit length of a byte slice against max_bits=<name>.  For
// bigint/biguint/bigpos kinds the caller passes x.BitLen(); for bytes kind
// the caller passes len(raw)*8 as a conservative upper bound.
func (fs fieldSchema) checkBitsLimit(bits int, limitSet FieldLimits) error {
	if fs.maxBits == "" {
		return nil
	}
	max, err := fs.getLimit(fs.maxBits, limitSet)
	if err != nil {
		return err
	}
	if bits > max {
		return fmt.Errorf("field %s: bit length %d exceeds max_bits=%d", fs.name, bits, max)
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
