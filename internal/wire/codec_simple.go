package wire

import (
	"fmt"
	"reflect"
	"unicode/utf8"
)

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

func (fs fieldSchema) decodeString(fv reflect.Value, raw []byte, limitSet LimitSet) error {
	if err := fs.checkByteLimits(raw, limitSet); err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("string is not valid UTF-8")
	}
	fv.SetString(string(raw))
	return nil
}
