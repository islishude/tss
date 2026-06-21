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
// partybytes, partybytepairs, nested, custom, bigint, biguint, bigpos,
// record, recordlist, map.
//
// The kind may be omitted from the struct tag, in which case it is inferred
// from the Go field type. Named primitive types (e.g. type SessionID [32]byte)
// are handled correctly. big.Int must always be declared explicitly.
//
// Pointer record, nested, custom, bigint, biguint, and bigpos fields may be
// marked with the "optional" option, for example
// `wire:"2,record,optional"`. An optional nil pointer is omitted during
// marshaling. When decoding, an absent optional field is left nil. Other
// pointer primitive shapes are rejected at schema-parse time.
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
	"bytes"
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
// are validated against length options (len, max_bytes) by the codec. When
// the field declares max_items, the returned bytes must start with a uint32
// item count, which the codec validates after marshaling.
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
// When the field declares max_items, its raw bytes must start with a uint32
// item count, which the codec validates before invoking UnmarshalWireValue.
type ValueUnmarshaler interface {
	UnmarshalWireValue([]byte) error
}

// MessageMarshaler is implemented by message types that provide their own
// complete canonical TLV message encoding.
//
// It is object-level, unlike ValueMarshaler, which only encodes one field
// value for `wire:",custom"` fields. The returned bytes must be a complete
// canonical TLV message: magic || type_id || version || field_body.
//
// Marshal reparses the returned frame and enforces its type, version,
// canonical field order, duplicate/tag-zero rejection, and trailing-data
// invariant before returning it to the caller.
type MessageMarshaler interface {
	MarshalWireMessage(opts ...MarshalOption) ([]byte, error)
}

// MessageUnmarshaler is implemented by message types that provide their own
// complete canonical TLV message decoding.
//
// It is object-level, unlike ValueUnmarshaler, which only decodes one field
// value for `wire:",custom"` fields. The implementation receives the
// complete TLV message bytes and must decode into the receiver.
//
// Unmarshal performs frame-level type, version, canonical-order, duplicate-tag,
// trailing-data, and configured size checks before invoking the implementation.
// Implementations must still validate their exact field schema and must not
// retain a reference to the input buffer.
type MessageUnmarshaler interface {
	UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error
}

func validateMarshaledMessage(raw []byte, msg Message, limits FrameLimits) error {
	version, fields, err := UnmarshalFieldsWithLimits(raw, msg.WireType(), limits)
	if err != nil {
		return err
	}
	if version != msg.WireVersion() {
		return fmt.Errorf("got version %d, want %d", version, msg.WireVersion())
	}
	canonical, err := MarshalFields(version, msg.WireType(), fields)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("message encoding is not canonical")
	}
	return nil
}

func marshalSelfCheckLimits(raw []byte) FrameLimits {
	return FrameLimits{
		MaxTotalBytes: len(raw),
		MaxFields:     maxRecordCount,
		MaxFieldBytes: len(raw),
	}
}

// runBeforeMarshalHook calls BeforeMarshalWire on msg if it implements
// BeforeMarshaler, falling back to the addressable value.
func runBeforeMarshalHook(msg any, v reflect.Value) error {
	if bm, ok := msg.(BeforeMarshaler); ok {
		return bm.BeforeMarshalWire()
	}
	if v.CanAddr() {
		if bm, ok := v.Addr().Interface().(BeforeMarshaler); ok {
			return bm.BeforeMarshalWire()
		}
	}
	return nil
}

// runValidateHook calls Validate on msg if it implements Validator,
// falling back to the addressable value.
func runValidateHook(msg any, v reflect.Value) error {
	if val, ok := msg.(Validator); ok {
		return val.Validate()
	}
	if v.CanAddr() {
		if val, ok := v.Addr().Interface().(Validator); ok {
			return val.Validate()
		}
	}
	return nil
}

// runAfterUnmarshalHook calls AfterUnmarshalWire on msg if it implements
// AfterUnmarshaler.
func runAfterUnmarshalHook(msg any) error {
	if au, ok := msg.(AfterUnmarshaler); ok {
		return au.AfterUnmarshalWire()
	}
	return nil
}

// Marshal encodes a struct using its "wire" struct tags into a
// canonical TLV envelope. msg must be a struct or pointer-to-struct
// implementing Message.
//
// Fields are encoded in ascending tag order. Missing, extra, or duplicate tags
// are rejected, except explicit optional pointer fields are omitted when nil.
// See the package documentation for the struct tag grammar.
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

	// Ensure v is addressable so pointer-receiver hook methods are visible.
	if !v.CanAddr() {
		newV := reflect.New(v.Type())
		newV.Elem().Set(v)
		v = newV.Elem()
	}

	var cfg marshalConfig
	for _, opt := range opts {
		opt.applyMarshal(&cfg)
	}

	if err := runBeforeMarshalHook(msg, v); err != nil {
		return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
	}

	if err := runValidateHook(msg, v); err != nil {
		return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
	}

	// Type-level codec hook: if the message provides its own complete TLV
	// encoding, delegate to it and bypass reflection-based field encoding.
	if mm, ok := msg.(MessageMarshaler); ok {
		raw, err := mm.MarshalWireMessage(opts...)
		if err != nil {
			return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
		}
		if raw == nil {
			return nil, fmt.Errorf("wire.Marshal %s: MarshalWireMessage returned nil", v.Type().Name())
		}
		if err := validateMarshaledMessage(raw, m, marshalSelfCheckLimits(raw)); err != nil {
			return nil, fmt.Errorf("wire.Marshal %s: invalid MarshalWireMessage output: %w", v.Type().Name(), err)
		}
		return raw, nil
	}
	if v.CanAddr() {
		if mm, ok := v.Addr().Interface().(MessageMarshaler); ok {
			raw, err := mm.MarshalWireMessage(opts...)
			if err != nil {
				return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
			}
			if raw == nil {
				return nil, fmt.Errorf("wire.Marshal %s: MarshalWireMessage returned nil", v.Type().Name())
			}
			if err := validateMarshaledMessage(raw, m, marshalSelfCheckLimits(raw)); err != nil {
				return nil, fmt.Errorf("wire.Marshal %s: invalid MarshalWireMessage output: %w", v.Type().Name(), err)
			}
			return raw, nil
		}
	}

	// Message assertion satisfied; proceed with reflection path.

	s, err := getSchema(v.Type())
	if err != nil {
		return nil, fmt.Errorf("wire.Marshal %s: %w", v.Type().Name(), err)
	}

	fields := make([]Field, 0, len(s.fields))
	for i := range s.fields {
		fs := &s.fields[i]
		fv := v.FieldByIndex(fs.index)
		if fs.shouldOmit(fv) {
			continue
		}
		value, err := fs.encode(fv, cfg.fieldLimits)
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
// WireType() and WireVersion(). The exact field set must match the schema:
// missing and extra fields are rejected, except explicit optional pointer fields
// may be absent and then remain nil.
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

	// Build a zero-value work copy. Decoding happens into work first so
	// that a failed decode never pollutes the original dst (fail-atomic).
	work := reflect.New(v.Type()).Elem()
	hookTarget := work.Addr().Interface()

	// Type-level codec hook: if the message provides its own complete TLV
	// decoding, delegate to it and bypass reflection-based field decoding.
	if um, ok := hookTarget.(MessageUnmarshaler); ok {
		limits := cfg.frameLimits.withDefaults()
		if err := validateMarshaledMessage(in, m, limits); err != nil {
			return fmt.Errorf("wire.Unmarshal %s: invalid message frame: %w", v.Type().Name(), err)
		}
		if err := um.UnmarshalWireMessage(in, opts...); err != nil {
			return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
		}
		if err := runAfterUnmarshalHook(hookTarget); err != nil {
			return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
		}
		if err := runValidateHook(hookTarget, work); err != nil {
			return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
		}
		v.Set(work)
		return nil
	}

	// Proceed with reflection path.
	limits := cfg.frameLimits.withDefaults()

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

	matched, err := s.matchFields(fields, "wire "+v.Type().Name())
	if err != nil {
		return err
	}

	for i := range s.fields {
		field := matched[i]
		if field == nil {
			continue
		}
		fs := &s.fields[i]
		fv := work.FieldByIndex(fs.index)
		if err := fs.decode(fv, field.Value, cfg.fieldLimits, limits); err != nil {
			return fmt.Errorf("wire %s field %s tag %d: %w", v.Type().Name(), fs.name, fs.tag, err)
		}
	}

	if err := runAfterUnmarshalHook(hookTarget); err != nil {
		return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
	}

	if err := runValidateHook(hookTarget, work); err != nil {
		return fmt.Errorf("wire.Unmarshal %s: %w", v.Type().Name(), err)
	}

	v.Set(work)
	return nil
}
