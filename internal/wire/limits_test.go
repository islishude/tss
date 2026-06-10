package wire_test

import (
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestUnmarshalRejectsOversizedInput(t *testing.T) {
	// Construct a minimal valid message then pad it beyond the limit.
	fields := []wire.Field{
		{Tag: 1, Value: []byte("hello")},
	}
	msg, err := wire.MarshalFields(1, "test.msg", fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	limits := wire.FrameLimits{
		MaxTotalBytes: len(msg) - 1, // deliberately too small
		MaxFields:     256,
		MaxFieldBytes: 1 << 20,
	}
	_, _, err = wire.UnmarshalFieldsWithLimits(msg, "test.msg", limits)
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestUnmarshalRejectsTooManyFields(t *testing.T) {
	// Build a message with more fields than the limit.
	var fields []wire.Field
	for i := range 5 {
		fields = append(fields, wire.Field{Tag: uint16(i + 1), Value: []byte{byte(i)}})
	}
	msg, err := wire.MarshalFields(1, "test.fields", fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	limits := wire.FrameLimits{
		MaxTotalBytes: 1 << 20,
		MaxFields:     3, // cap at 3 fields
		MaxFieldBytes: 1 << 20,
	}
	_, _, err = wire.UnmarshalFieldsWithLimits(msg, "test.fields", limits)
	if err == nil {
		t.Fatal("expected error for too many fields")
	}
}

func TestUnmarshalRejectsOversizedField(t *testing.T) {
	value := make([]byte, 100)
	fields := []wire.Field{
		{Tag: 1, Value: value},
	}
	msg, err := wire.MarshalFields(1, "test.bigfield", fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	limits := wire.FrameLimits{
		MaxTotalBytes: 1 << 20,
		MaxFields:     256,
		MaxFieldBytes: 50, // cap at 50 bytes per field
	}
	_, _, err = wire.UnmarshalFieldsWithLimits(msg, "test.bigfield", limits)
	if err == nil {
		t.Fatal("expected error for oversized field")
	}
}

func TestUnmarshalWithLimitsRejectsWrongType(t *testing.T) {
	fields := []wire.Field{
		{Tag: 1, Value: []byte("x")},
	}
	msg, err := wire.MarshalFields(1, "test.abc", fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	limits := wire.DefaultFrameLimits()
	_, _, err = wire.UnmarshalFieldsWithLimits(msg, "test.xyz", limits)
	if err == nil {
		t.Fatal("expected error for wrong wire type")
	}
}

func TestUnmarshalWithLimitsValidMessage(t *testing.T) {
	fields := []wire.Field{
		{Tag: 1, Value: []byte("hello")},
		{Tag: 3, Value: []byte("world")},
	}
	msg, err := wire.MarshalFields(1, "test.valid", fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	limits := wire.DefaultFrameLimits()
	version, parsed, err := wire.UnmarshalFieldsWithLimits(msg, "test.valid", limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != 1 {
		t.Errorf("version: got %d, want 1", version)
	}
	if len(parsed) != 2 {
		t.Errorf("fields: got %d, want 2", len(parsed))
	}
}

func TestReadBytesWithLimitRejectsOversized(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x00, 0x10} // length = 16
	_, _, err := wire.ReadBytesWithLimit(raw, 0, 8)
	if err == nil {
		t.Fatal("expected error for oversized byte field")
	}
}

func TestDecodeBytesListWithLimitRejectsTooManyItems(t *testing.T) {
	// Encode a list with 3 items.
	var items [][]byte
	for i := range 3 {
		items = append(items, []byte{byte(i)})
	}
	raw := wire.EncodeBytesList(items)

	_, err := wire.DecodeBytesListWithLimit(raw, 2, 0)
	if err == nil {
		t.Fatal("expected error for too many list items")
	}
}

func TestDecodeUint32ListWithLimitRejectsTooManyItems(t *testing.T) {
	raw := wire.EncodeUint32List([]uint32{1, 2, 3, 4, 5})

	_, err := wire.DecodeUint32ListWithLimit[uint32](raw, 3)
	if err == nil {
		t.Fatal("expected error for too many uint32 list items")
	}
}
