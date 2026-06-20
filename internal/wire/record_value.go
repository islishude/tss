package wire

import (
	"errors"
	"fmt"
	"reflect"
)

// MarshalOptionsView exposes the effective options passed to a
// MessageMarshaler implementation.
type MarshalOptionsView struct {
	FieldLimits FieldLimits
}

// UnmarshalOptionsView exposes the effective options passed to a
// MessageUnmarshaler implementation.
type UnmarshalOptionsView struct {
	FrameLimits FrameLimits
	FieldLimits FieldLimits
}

// ResolveMarshalOptions returns the field limits supplied to a direct message
// codec. A nil FieldLimits value means the caller supplied no semantic limits.
func ResolveMarshalOptions(opts ...MarshalOption) MarshalOptionsView {
	cfg := marshalConfig{}
	for _, opt := range opts {
		opt.applyMarshal(&cfg)
	}
	return MarshalOptionsView{FieldLimits: cfg.fieldLimits}
}

// ResolveUnmarshalOptions returns the effective frame and field limits supplied
// to a direct message codec. DefaultFrameLimits is used only when the caller did
// not provide any frame limit.
func ResolveUnmarshalOptions(opts ...UnmarshalOption) UnmarshalOptionsView {
	cfg := unmarshalConfig{}
	for _, opt := range opts {
		opt.applyUnmarshal(&cfg)
	}
	if cfg.frameLimits.MaxTotalBytes == 0 &&
		cfg.frameLimits.MaxFields == 0 &&
		cfg.frameLimits.MaxFieldBytes == 0 {
		cfg.frameLimits = DefaultFrameLimits()
	}
	return UnmarshalOptionsView{
		FrameLimits: cfg.frameLimits,
		FieldLimits: cfg.fieldLimits,
	}
}

// MarshalRecordValue encodes a struct or pointer-to-struct as a canonical
// record field value. It is intended for custom field implementations that need
// to preserve the same record-body bytes as the "record" kind.
func MarshalRecordValue(v any, opts ...MarshalOption) ([]byte, error) {
	if v == nil {
		return nil, errors.New("nil record value")
	}
	resolved := ResolveMarshalOptions(opts...)
	return marshalRecordValue(reflect.ValueOf(v), resolved.FieldLimits)
}

// UnmarshalRecordValue decodes a canonical record field value into dst. dst
// must be a non-nil pointer to a struct or pointer-to-struct.
func UnmarshalRecordValue(raw []byte, dst any, opts ...UnmarshalOption) error {
	if dst == nil {
		return errors.New("nil record destination")
	}
	resolved := ResolveUnmarshalOptions(opts...)
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("record destination must be a non-nil pointer")
	}
	if resolved.FrameLimits.MaxTotalBytes > 0 && len(raw) > resolved.FrameLimits.MaxTotalBytes {
		return fmt.Errorf("record input too large: %d > %d", len(raw), resolved.FrameLimits.MaxTotalBytes)
	}
	return unmarshalRecordValue(raw, rv, resolved.FieldLimits, resolved.FrameLimits)
}

// MarshalRecordFields encodes precomputed fields as a canonical record field
// value. It preserves the same field-body format used by the "record" kind.
func MarshalRecordFields(fields []Field) ([]byte, error) {
	return marshalFieldBody(fields)
}

// UnmarshalRecordFieldsWithLimits decodes a canonical record field value. It
// rejects trailing bytes and returns copied field values.
func UnmarshalRecordFieldsWithLimits(raw []byte, limits FrameLimits, name string) ([]Field, error) {
	if limits.MaxTotalBytes > 0 && len(raw) > limits.MaxTotalBytes {
		return nil, fmt.Errorf("record input too large: %d > %d", len(raw), limits.MaxTotalBytes)
	}
	fields, offset, err := unmarshalFieldBody(raw, 0, limits, name)
	if err != nil {
		return nil, err
	}
	if offset != len(raw) {
		return nil, errors.New("trailing record data")
	}
	return fields, nil
}

// MarshalMessageBody encodes precomputed fields as a complete canonical TLV
// message for a type-level MessageMarshaler implementation.
func MarshalMessageBody(msg Message, fields []Field) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("nil wire message")
	}
	return MarshalFields(msg.WireVersion(), msg.WireType(), fields)
}

// UnmarshalMessageBody decodes a complete canonical TLV message for a
// type-level MessageUnmarshaler implementation and validates the message type
// and version before returning copied fields. It applies the caller's frame
// options exactly as wire.Unmarshal would.
func UnmarshalMessageBody(raw []byte, msg Message, opts ...UnmarshalOption) ([]Field, error) {
	if msg == nil {
		return nil, errors.New("nil wire message")
	}
	resolved := ResolveUnmarshalOptions(opts...)
	version, fields, err := UnmarshalFieldsWithLimits(raw, msg.WireType(), resolved.FrameLimits)
	if err != nil {
		return nil, err
	}
	if version != msg.WireVersion() {
		return nil, fmt.Errorf("wire %s: got version %d, want %d", msg.WireType(), version, msg.WireVersion())
	}
	return fields, nil
}
