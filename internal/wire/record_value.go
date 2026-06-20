package wire

import (
	"errors"
	"fmt"
	"reflect"
)

// MarshalRecordValue encodes a struct or pointer-to-struct as a canonical
// record field value. It is intended for custom field implementations that need
// to preserve the same record-body bytes as the "record" kind.
func MarshalRecordValue(v any, opts ...MarshalOption) ([]byte, error) {
	if v == nil {
		return nil, errors.New("nil record value")
	}
	cfg := marshalConfig{}
	for _, opt := range opts {
		opt.applyMarshal(&cfg)
	}
	return marshalRecordValue(reflect.ValueOf(v), cfg.fieldLimits)
}

// UnmarshalRecordValue decodes a canonical record field value into dst. dst
// must be a non-nil pointer to a struct or pointer-to-struct.
func UnmarshalRecordValue(raw []byte, dst any, opts ...UnmarshalOption) error {
	if dst == nil {
		return errors.New("nil record destination")
	}
	cfg := unmarshalConfig{frameLimits: DefaultFrameLimits()}
	for _, opt := range opts {
		opt.applyUnmarshal(&cfg)
	}
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("record destination must be a non-nil pointer")
	}
	if cfg.frameLimits.MaxTotalBytes > 0 && len(raw) > cfg.frameLimits.MaxTotalBytes {
		return fmt.Errorf("record input too large: %d > %d", len(raw), cfg.frameLimits.MaxTotalBytes)
	}
	return unmarshalRecordValue(raw, rv, cfg.fieldLimits, cfg.frameLimits)
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
// and version before returning copied fields.
func UnmarshalMessageBody(raw []byte, msg Message, limits FrameLimits) ([]Field, error) {
	if msg == nil {
		return nil, errors.New("nil wire message")
	}
	version, fields, err := UnmarshalFieldsWithLimits(raw, msg.WireType(), limits)
	if err != nil {
		return nil, err
	}
	if version != msg.WireVersion() {
		return nil, fmt.Errorf("wire %s: got version %d, want %d", msg.WireType(), version, msg.WireVersion())
	}
	return fields, nil
}
