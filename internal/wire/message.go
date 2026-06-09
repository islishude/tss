// Package wire provides a strict canonical TLV binary encoding for
// cryptographic protocol messages.
//
// # Object-Level API (Production)
//
// All production message types use struct-tag-driven Marshal/Unmarshal:
//
//	type MyMsg struct {
//	    Data []byte `wire:"1,bytes"`
//	}
//	func (MyMsg) WireType() string    { return "my.type" }
//	func (MyMsg) WireVersion() uint16 { return 1 }
//
//	raw, _ := wire.Marshal(msg)
//	var decoded MyMsg
//	wire.Unmarshal(raw, &decoded)
//
// Supported kinds: u8, u16, u32, bool, bytes, string, u32list, byteslist,
// partybytes, partybytepairs, nested, custom. All tagged fields are required;
// missing and extra fields are rejected.
//
// The "custom" kind delegates field value encoding to the field type via
// the ValueMarshaler and ValueUnmarshaler interfaces. This lets domain types
// define their own canonical bytes without internal/wire importing them.
//
// # Field-Level API (Tests Only)
//
// MarshalFields, UnmarshalFields, UnmarshalFieldsWithLimits, and
// RequireExactTags are restricted to test infrastructure (internal/testutil,
// mutation tests, fuzz tests). Production code must use the object-level API.
package wire

import (
	"fmt"
	"reflect"
)

// Message is the interface that every wire-encodable type must implement.
// WireType returns the canonical type identifier used in the TLV envelope.
// WireVersion returns the expected version number for this message.
type Message interface {
	WireType() string
	WireVersion() uint16
}

// Validator is an optional interface for types that need validation
// after unmarshaling or before marshaling. Validate is called by
// Marshal (before encoding) and Unmarshal (after decoding).
type Validator interface {
	Validate() error
}

// BeforeMarshaler is an optional interface called by Marshal before
// encoding. Use it to populate derived fields or canonicalize values.
type BeforeMarshaler interface {
	BeforeMarshalWire() error
}

// AfterUnmarshaler is an optional interface called by Unmarshal after
// decoding fields but before Validate. Use it to reconstruct derived
// state or check invariants that span multiple fields.
type AfterUnmarshaler interface {
	AfterUnmarshalWire() error
}

// ValueMarshaler is implemented by types that can encode themselves into
// a canonical wire field value. It is used by the "custom" wire kind to
// let domain types define their own TLV field value encoding without
// importing internal/wire.
//
// MarshalWireValue must return a non-nil byte slice. The returned bytes
// are validated against length options (len, max_bytes) by the codec.
type ValueMarshaler interface {
	MarshalWireValue() ([]byte, error)
}

// ValueUnmarshaler is implemented by types that can decode themselves from
// raw wire field value bytes. It is used by the "custom" wire kind to
// let domain types reconstruct themselves from TLV field values.
//
// The implementation must copy the input bytes — it must not retain a
// reference to the underlying decode buffer. Length options (len,
// max_bytes) are validated by the codec before UnmarshalWireValue is called.
type ValueUnmarshaler interface {
	UnmarshalWireValue([]byte) error
}

// Marshal encodes a struct using its "wire" struct tags into a
// canonical TLV envelope. msg must be a struct or pointer-to-struct
// implementing Message.
//
// Fields are encoded in ascending tag order. Missing, extra, or
// duplicate tags are rejected. See the package documentation for the
// struct tag grammar.
func Marshal(msg any, opts ...MarshalOption) ([]byte, error) {
	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, fmt.Errorf("wire.Marshal: nil pointer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("wire.Marshal: expected struct, got %s", v.Kind())
	}

	m, ok := msg.(Message)
	if !ok {
		if v.CanAddr() {
			m, ok = v.Addr().Interface().(Message)
		}
		if !ok {
			return nil, fmt.Errorf("wire.Marshal: %s does not implement Message", v.Type())
		}
	}

	var cfg marshalConfig
	for _, opt := range opts {
		opt.applyMarshal(&cfg)
	}

	// BeforeMarshalWire hook — try value, then pointer.
	if bm, ok := msg.(BeforeMarshaler); ok {
		if err := bm.BeforeMarshalWire(); err != nil {
			return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
		}
	} else if v.CanAddr() {
		if bm, ok := v.Addr().Interface().(BeforeMarshaler); ok {
			if err := bm.BeforeMarshalWire(); err != nil {
				return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
			}
		}
	}

	// Validate before marshal — try value, then pointer.
	if val, ok := msg.(Validator); ok {
		if err := val.Validate(); err != nil {
			return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
		}
	} else if v.CanAddr() {
		if val, ok := v.Addr().Interface().(Validator); ok {
			if err := val.Validate(); err != nil {
				return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
			}
		}
	}

	s, err := getSchema(v.Type())
	if err != nil {
		return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
	}

	fields := make([]Field, 0, len(s.fields))
	for i := range s.fields {
		fs := &s.fields[i]
		fv := v.FieldByIndex(fs.index)
		value, err := fs.encode(fv, cfg.limitSet)
		if err != nil {
			return nil, fmt.Errorf("wire %s field %s tag %d: %w", v.Type().Name(), fs.name, fs.tag, err)
		}
		fields = append(fields, Field{Tag: fs.tag, Value: value})
	}

	return MarshalFields(m.WireVersion(), m.WireType(), fields)
}

// Unmarshal decodes a canonical TLV envelope into dst using its "wire"
// struct tags. dst must be a non-nil pointer to a struct implementing
// Message.
//
// The decoded type ID and version are validated against dst's
// WireType() and WireVersion().  The exact field set must match the
// schema — missing and extra fields are rejected.
func Unmarshal(in []byte, dst any, opts ...UnmarshalOption) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("wire.Unmarshal: dst must be non-nil pointer to struct, got %T", dst)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("wire.Unmarshal: dst must be pointer to struct, got pointer to %s", v.Kind())
	}

	m, ok := dst.(Message)
	if !ok {
		return fmt.Errorf("wire.Unmarshal: %s does not implement Message", v.Type())
	}

	var cfg unmarshalConfig
	for _, opt := range opts {
		opt.applyUnmarshal(&cfg)
	}

	limits := cfg.limits
	if limits.MaxTotalBytes == 0 && limits.MaxFields == 0 && limits.MaxFieldBytes == 0 {
		limits = DefaultLimits()
	}

	version, fields, err := UnmarshalFieldsWithLimits(in, m.WireType(), limits)
	if err != nil {
		return err
	}

	if version != m.WireVersion() {
		return fmt.Errorf("wire %s: got version %d, want %d", v.Type().Name(), version, m.WireVersion())
	}

	s, err := getSchema(v.Type())
	if err != nil {
		return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
	}

	// Exact field set: require same count and matching tag sequence.
	if len(fields) != len(s.fields) {
		return fmt.Errorf("wire %s: got %d fields, want %d", v.Type().Name(), len(fields), len(s.fields))
	}
	for i := range s.fields {
		if fields[i].Tag != s.fields[i].tag {
			return fmt.Errorf("wire %s: unexpected field tag %d at index %d, want %d",
				v.Type().Name(), fields[i].Tag, i, s.fields[i].tag)
		}
	}

	for i := range s.fields {
		fs := &s.fields[i]
		fv := v.FieldByIndex(fs.index)
		if err := fs.decode(fv, fields[i].Value, cfg.limitSet); err != nil {
			return fmt.Errorf("wire %s field %s tag %d: %w", v.Type().Name(), fs.name, fs.tag, err)
		}
	}

	// AfterUnmarshalWire hook.
	if au, ok := dst.(AfterUnmarshaler); ok {
		if err := au.AfterUnmarshalWire(); err != nil {
			return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
		}
	}

	// Validate.
	if val, ok := dst.(Validator); ok {
		if err := val.Validate(); err != nil {
			return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
		}
	}

	return nil
}
