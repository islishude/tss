package wire

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
)

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
func (fs fieldSchema) encodeBigIntDispatch(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	x := bigIntFromValue(fv)
	if fv.Kind() == reflect.Pointer && x == nil {
		return nil, fmt.Errorf("wire: required bigint field %s tag %d is nil", fs.name, fs.tag)
	}
	bits := 0
	if x != nil {
		bits = x.BitLen()
	}
	if err := fs.checkBitsLimit(bits, limitSet); err != nil {
		return nil, err
	}
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
func (fs fieldSchema) encodeBigUintDispatch(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	x := bigIntFromValue(fv)
	if fv.Kind() == reflect.Pointer && x == nil {
		return nil, fmt.Errorf("wire: required biguint field %s tag %d is nil", fs.name, fs.tag)
	}
	bits := 0
	if x != nil {
		bits = x.BitLen()
	}
	if err := fs.checkBitsLimit(bits, limitSet); err != nil {
		return nil, err
	}
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
func (fs fieldSchema) encodeBigPosDispatch(fv reflect.Value, limitSet FieldLimits) ([]byte, error) {
	x := bigIntFromValue(fv)
	bits := 0
	if x != nil {
		bits = x.BitLen()
	}
	if err := fs.checkBitsLimit(bits, limitSet); err != nil {
		return nil, err
	}
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
func (fs fieldSchema) decodeBigIntDispatch(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
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
	if err := fs.checkBitsLimit(x.BitLen(), limitSet); err != nil {
		return err
	}
	setBigIntValue(fv, x)
	return nil
}

// decodeBigUintDispatch decodes raw bytes into an unsigned integer field.
func (fs fieldSchema) decodeBigUintDispatch(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
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
	if err := fs.checkBitsLimit(x.BitLen(), limitSet); err != nil {
		return err
	}
	setBigIntValue(fv, x)
	return nil
}

// decodeBigPosDispatch decodes raw bytes into a positive integer field.
func (fs fieldSchema) decodeBigPosDispatch(fv reflect.Value, raw []byte, limitSet FieldLimits) error {
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
	if err := fs.checkBitsLimit(x.BitLen(), limitSet); err != nil {
		return err
	}
	setBigIntValue(fv, x)
	return nil
}
