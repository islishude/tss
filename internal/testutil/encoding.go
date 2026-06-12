package testutil

import (
	"bytes"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

// RewriteWireField returns a copy of raw with the given TLV field's value
// replaced. The wire type string must match the top-level message type.
func RewriteWireField(raw []byte, wireType string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, wireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.MarshalFields(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}

// RewriteNestedWireField returns a copy of raw with a nested TLV field value
// replaced. The field identified by outerTag is decoded as innerType, the
// inner field innerTag is replaced, and the result is re-encoded.
func RewriteNestedWireField(raw []byte, outerType string, outerTag uint16, innerType string, innerTag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, outerType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag != outerTag {
			continue
		}
		inner, err := RewriteWireField(fields[i].Value, innerType, innerTag, value)
		if err != nil {
			return nil, err
		}
		fields[i].Value = inner
		return wire.MarshalFields(version, outerType, fields)
	}
	return nil, fmt.Errorf("missing outer wire field %d", outerTag)
}

// MustFieldTag is like wire.FieldTag but panics on error. It is intended for
// test struct literals where an error return is impractical.
func MustFieldTag(model any, fieldName string) uint16 {
	tag, err := wire.FieldTag(model, fieldName)
	if err != nil {
		panic(err)
	}
	return tag
}

// RewriteWireFieldByName is like RewriteWireField but resolves the field tag
// from the Go struct field name. model must be a zero-value instance of the
// payload struct (e.g. presignRound1Payload{}).
func RewriteWireFieldByName(raw []byte, wireType string, model any, fieldName string, value []byte) ([]byte, error) {
	tag, err := wire.FieldTag(model, fieldName)
	if err != nil {
		return nil, err
	}
	return RewriteWireField(raw, wireType, tag, value)
}

// RewriteNestedWireFieldByName is like RewriteNestedWireField but resolves both
// outer and inner field tags from Go struct field names.
func RewriteNestedWireFieldByName(raw []byte, outerType string, outerModel any, outerField string, innerType string, innerModel any, innerField string, value []byte) ([]byte, error) {
	outerTag, err := wire.FieldTag(outerModel, outerField)
	if err != nil {
		return nil, err
	}
	innerTag, err := wire.FieldTag(innerModel, innerField)
	if err != nil {
		return nil, err
	}
	return RewriteNestedWireField(raw, outerType, outerTag, innerType, innerTag, value)
}

// MarshalFieldsByName marshals fields by struct field name rather than tag number.
// model must be a zero-value instance of the wire struct.
func MarshalFieldsByName(version uint16, wireType string, model any, named map[string][]byte) ([]byte, error) {
	fields := make([]wire.Field, 0, len(named))
	for name, value := range named {
		tag, err := wire.FieldTag(model, name)
		if err != nil {
			return nil, err
		}
		fields = append(fields, wire.Field{
			Tag:   tag,
			Value: value,
		})
	}
	return wire.MarshalFields(version, wireType, fields)
}

// AssertDeterministicRoundTrip checks that a value survives a marshal →
// unmarshal → marshal cycle and produces identical bytes both times.
// It calls t.Fatal on any error.
func AssertDeterministicRoundTrip[P any](
	tb interface{ Fatal(...any) },
	p P,
	marshal func(P) ([]byte, error),
	unmarshal func([]byte) (P, error),
) {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
	raw, err := marshal(p)
	if err != nil {
		tb.Fatal(fmt.Sprintf("initial marshal: %v", err))
		return
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		tb.Fatal(fmt.Sprintf("unmarshal: %v", err))
		return
	}
	again, err := marshal(decoded)
	if err != nil {
		tb.Fatal(fmt.Sprintf("second marshal: %v", err))
		return
	}
	if !bytes.Equal(raw, again) {
		tb.Fatal("payload did not remarshal deterministically")
	}
}
