package testutil

import (
	"bytes"
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

// RewriteWireField returns a copy of raw with the given TLV field's value
// replaced. The wire type string must match the top-level message type.
func RewriteWireField(raw []byte, wireType string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, wireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.Marshal(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}

// RewriteNestedWireField returns a copy of raw with a nested TLV field value
// replaced. The field identified by outerTag is decoded as innerType, the
// inner field innerTag is replaced, and the result is re-encoded.
func RewriteNestedWireField(raw []byte, outerType string, outerTag uint16, innerType string, innerTag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, outerType)
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
		return wire.Marshal(version, outerType, fields)
	}
	return nil, fmt.Errorf("missing outer wire field %d", outerTag)
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
