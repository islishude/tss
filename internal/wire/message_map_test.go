package wire

import (
	"bytes"
	"reflect"
	"testing"
)

// ---- test types for map ----

type testPartyID uint32

// mapBytesMessage uses []byte values.
type mapBytesMessage struct {
	Items map[testPartyID][]byte `wire:"1,map,max_items=parties,max_bytes=field"`
}

func (m mapBytesMessage) WireType() string    { return "wire.test.map.bytes" }
func (m mapBytesMessage) WireVersion() uint16 { return 1 }

// mapStringMessage uses string values.
type mapStringMessage struct {
	Items map[uint32]string `wire:"1,map,max_items=parties,max_bytes=field"`
}

func (m mapStringMessage) WireType() string    { return "wire.test.map.string" }
func (m mapStringMessage) WireVersion() uint16 { return 1 }

// mapU32Message uses uint32 values.
type mapU32Message struct {
	Items map[uint32]uint32 `wire:"1,map"`
}

func (m mapU32Message) WireType() string    { return "wire.test.map.u32" }
func (m mapU32Message) WireVersion() uint16 { return 1 }

// mapBoolMessage uses bool values.
type mapBoolMessage struct {
	Items map[uint32]bool `wire:"1,map"`
}

func (m mapBoolMessage) WireType() string    { return "wire.test.map.bool" }
func (m mapBoolMessage) WireVersion() uint16 { return 1 }

// mapNilMessage is used to test nil map encoding.
type mapNilMessage struct {
	Items map[uint32][]byte `wire:"1,map,max_items=parties,max_bytes=field"`
}

func (m mapNilMessage) WireType() string    { return "wire.test.map.nil" }
func (m mapNilMessage) WireVersion() uint16 { return 1 }

// mapRecord is a record type used as a map value.
type mapRecord struct {
	Name  string `wire:"1,string"`
	Value uint32 `wire:"2,u32"`
}

// mapRecordMessage uses record values.
type mapRecordMessage struct {
	Items map[uint32]mapRecord `wire:"1,map,max_items=parties"`
}

func (m mapRecordMessage) WireType() string    { return "wire.test.map.record" }
func (m mapRecordMessage) WireVersion() uint16 { return 1 }

// mapPtrRecordMessage uses *record values.
type mapPtrRecordMessage struct {
	Items map[uint32]*mapRecord `wire:"1,map,max_items=parties"`
}

func (m mapPtrRecordMessage) WireType() string    { return "wire.test.map.ptrrecord" }
func (m mapPtrRecordMessage) WireVersion() uint16 { return 1 }

// mapRecordWithOptional is a record map value with an optional record field.
type mapRecordWithOptional struct {
	Value uint32     `wire:"1,u32"`
	Inner *mapRecord `wire:"2,record,optional"`
}

// mapOptionalRecordMessage uses record values with optional record fields.
type mapOptionalRecordMessage struct {
	Items map[uint32]mapRecordWithOptional `wire:"1,map,max_items=parties"`
}

func (m mapOptionalRecordMessage) WireType() string    { return "wire.test.map.optionalrecord" }
func (m mapOptionalRecordMessage) WireVersion() uint16 { return 1 }

// mapCustomValue implements ValueMarshaler/ValueUnmarshaler.
type mapCustomValue struct {
	data []byte
}

func (c mapCustomValue) MarshalWireValue() ([]byte, error) {
	if c.data == nil {
		return []byte{}, nil
	}
	out := make([]byte, len(c.data))
	copy(out, c.data)
	return out, nil
}

func (c *mapCustomValue) UnmarshalWireValue(in []byte) error {
	c.data = make([]byte, len(in))
	copy(c.data, in)
	return nil
}

// mapCustomMessage uses custom (ValueMarshaler) values.
type mapCustomMessage struct {
	Items map[uint32]mapCustomValue `wire:"1,map,max_items=parties,max_bytes=field"`
}

func (m mapCustomMessage) WireType() string    { return "wire.test.map.custom" }
func (m mapCustomMessage) WireVersion() uint16 { return 1 }

// mapFixedLenMessage uses fixed-length value (array).
type mapFixedLenMessage struct {
	Items map[uint32][4]byte `wire:"1,map,max_items=parties"`
}

func (m mapFixedLenMessage) WireType() string    { return "wire.test.map.fixedlen" }
func (m mapFixedLenMessage) WireVersion() uint16 { return 1 }

// ---- mapEncodeRawEntries is a test helper to construct raw map field values
// with explicit ordering (for testing unsorted/duplicate scenarios).

func mapEncodeRawEntries(entries ...mapRawEntry) []byte {
	out := Uint32(uint32(len(entries)))
	for _, e := range entries {
		out = AppendBytes(out, Uint32(e.key))
		out = AppendBytes(out, e.value)
	}
	return out
}

type mapRawEntry struct {
	key   uint32
	value []byte
}

// ---- map roundtrip tests ----

func TestMapBytesRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapBytesMessage{
		Items: map[testPartyID][]byte{
			3: {0x03, 0x03},
			1: {0x01},
			2: {0x02, 0x02, 0x02},
		},
	}

	limits := FieldLimits{"parties": 10, "field": 100}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(decoded.Items))
	}
	for k, v := range orig.Items {
		if !bytes.Equal(decoded.Items[k], v) {
			t.Fatalf("key %d: got %v, want %v", k, decoded.Items[k], v)
		}
	}
}

func TestMapNamedKeyRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapBytesMessage{
		Items: map[testPartyID][]byte{
			testPartyID(5):  {0x05},
			testPartyID(10): {0x0a, 0x0b},
		},
	}

	limits := FieldLimits{"parties": 10, "field": 100}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(decoded.Items))
	}
}

func TestMapStringRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapStringMessage{
		Items: map[uint32]string{
			1: "hello",
			2: "world",
		},
	}

	limits := FieldLimits{"parties": 10, "field": 100}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapStringMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1] != "hello" || decoded.Items[2] != "world" {
		t.Fatalf("got %v", decoded.Items)
	}
}

func TestMapU32Roundtrip(t *testing.T) {
	t.Parallel()

	orig := mapU32Message{
		Items: map[uint32]uint32{1: 100, 2: 200},
	}

	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapU32Message
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1] != 100 || decoded.Items[2] != 200 {
		t.Fatalf("got %v", decoded.Items)
	}
}

func TestMapBoolRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapBoolMessage{
		Items: map[uint32]bool{1: true, 2: false},
	}

	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBoolMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1] != true || decoded.Items[2] != false {
		t.Fatalf("got %v", decoded.Items)
	}
}

// ---- nil/empty map tests ----

func TestMapNilAndEmptyEncodeSame(t *testing.T) {
	t.Parallel()

	limits := FieldLimits{"parties": 10, "field": 100}

	nilMsg := mapNilMessage{Items: nil}
	nilRaw, err := Marshal(nilMsg, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	emptyMsg := mapNilMessage{Items: map[uint32][]byte{}}
	emptyRaw, err := Marshal(emptyMsg, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(nilRaw, emptyRaw) {
		t.Fatal("nil map and empty map should encode identically")
	}
}

// ---- deterministic encoding tests ----

func TestMapDeterministicEncoding(t *testing.T) {
	t.Parallel()

	limits := FieldLimits{"parties": 10, "field": 100}

	// Build the same logical map with different insertion orders.
	makeMsg := func(keys []testPartyID) mapBytesMessage {
		m := mapBytesMessage{Items: make(map[testPartyID][]byte)}
		for _, k := range keys {
			m.Items[k] = []byte{byte(k)}
		}
		return m
	}

	order1 := []testPartyID{3, 1, 2}
	order2 := []testPartyID{2, 3, 1}
	order3 := []testPartyID{1, 2, 3}

	raw1, err := Marshal(makeMsg(order1), WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := Marshal(makeMsg(order2), WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}
	raw3, err := Marshal(makeMsg(order3), WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw1, raw2) || !bytes.Equal(raw2, raw3) {
		t.Fatal("different insertion orders should produce identical wire bytes")
	}
}

func TestMapSortedByCanonicalKey(t *testing.T) {
	t.Parallel()

	limits := FieldLimits{"parties": 10, "field": 100}

	orig := mapBytesMessage{
		Items: map[testPartyID][]byte{
			3: {0x03},
			1: {0x01},
			2: {0x02},
		},
	}

	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	// Decode the field body to verify key ordering.
	version, fields, err := UnmarshalFields(raw, "wire.test.map.bytes")
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("got version %d, want 1", version)
	}

	// The map field body should have keys 1, 2, 3 in ascending order.
	mapRaw := fields[0].Value
	count, offset, err := ReadUint32(mapRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("got %d entries, want 3", count)
	}

	var keys []uint32
	for i := 0; i < int(count); i++ {
		keyBytes, next, err := ReadBytes(mapRaw, offset)
		if err != nil {
			t.Fatal(err)
		}
		offset = next

		k, err := DecodeUint32(keyBytes)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)

		// Skip value.
		_, offset, err = ReadBytes(mapRaw, offset)
		if err != nil {
			t.Fatal(err)
		}
	}

	if keys[0] != 1 || keys[1] != 2 || keys[2] != 3 {
		t.Fatalf("keys not sorted: %v", keys)
	}
}

// ---- error path tests ----

func TestMapUnmarshalRejectsUnsortedEntries(t *testing.T) {
	t.Parallel()

	// Manually construct a message with unsorted map entries.
	entries := mapEncodeRawEntries(
		mapRawEntry{key: 2, value: []byte{0x02}},
		mapRawEntry{key: 1, value: []byte{0x01}}, // out of order
	)

	raw, err := MarshalFields(1, "wire.test.map.bytes", []Field{
		{Tag: 1, Value: entries},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	limits := FieldLimits{"parties": 10, "field": 100}
	err = Unmarshal(raw, &decoded, WithFieldLimits(limits))
	if err == nil {
		t.Fatal("expected error for unsorted map entries")
	}
}

func TestMapUnmarshalRejectsDuplicateKey(t *testing.T) {
	t.Parallel()

	entries := mapEncodeRawEntries(
		mapRawEntry{key: 1, value: []byte{0x01}},
		mapRawEntry{key: 1, value: []byte{0x01}}, // duplicate
	)

	raw, err := MarshalFields(1, "wire.test.map.bytes", []Field{
		{Tag: 1, Value: entries},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	limits := FieldLimits{"parties": 10, "field": 100}
	err = Unmarshal(raw, &decoded, WithFieldLimits(limits))
	if err == nil {
		t.Fatal("expected error for duplicate map key")
	}
}

func TestMapMaxItemsEnforced(t *testing.T) {
	t.Parallel()

	orig := mapBytesMessage{
		Items: map[testPartyID][]byte{
			1: {0x01},
			2: {0x02},
			3: {0x03},
		},
	}

	limits := FieldLimits{"parties": 2, "field": 100}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err == nil {
		t.Fatal("expected max_items violation error")
	}

	// Within limit should succeed.
	limits["parties"] = 10
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
}

func TestMapMaxBytesEnforced(t *testing.T) {
	t.Parallel()

	orig := mapBytesMessage{
		Items: map[testPartyID][]byte{
			1: bytes.Repeat([]byte{0x01}, 200),
		},
	}

	limits := FieldLimits{"parties": 10, "field": 100}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err == nil {
		t.Fatal("expected max_bytes violation error")
	}
}

func TestMapRecordValueRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapRecordMessage{
		Items: map[uint32]mapRecord{
			1: {Name: "first", Value: 100},
			2: {Name: "second", Value: 200},
		},
	}

	limits := FieldLimits{"parties": 10}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapRecordMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1].Name != "first" || decoded.Items[1].Value != 100 {
		t.Fatalf("record roundtrip mismatch: %+v", decoded.Items[1])
	}
	if decoded.Items[2].Name != "second" || decoded.Items[2].Value != 200 {
		t.Fatalf("record roundtrip mismatch: %+v", decoded.Items[2])
	}
}

func TestMapPtrRecordValueRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapPtrRecordMessage{
		Items: map[uint32]*mapRecord{
			1: {Name: "hello", Value: 42},
		},
	}

	limits := FieldLimits{"parties": 10}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapPtrRecordMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1].Name != "hello" || decoded.Items[1].Value != 42 {
		t.Fatalf("record roundtrip mismatch: %+v", decoded.Items[1])
	}
}

func TestMapRecordValueOptionalRecordRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapOptionalRecordMessage{
		Items: map[uint32]mapRecordWithOptional{
			1: {Value: 10},
			2: {Value: 20, Inner: &mapRecord{Name: "present", Value: 99}},
		},
	}

	limits := FieldLimits{"parties": 10}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapOptionalRecordMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1].Inner != nil {
		t.Fatal("expected absent optional map record field to decode as nil")
	}
	if decoded.Items[1].Value != 10 {
		t.Fatalf("value: got %d, want 10", decoded.Items[1].Value)
	}
	if decoded.Items[2].Inner == nil {
		t.Fatal("expected present optional map record field to decode as non-nil")
	}
	if decoded.Items[2].Inner.Name != "present" || decoded.Items[2].Inner.Value != 99 {
		t.Fatalf("inner roundtrip mismatch: %+v", decoded.Items[2].Inner)
	}
}

func TestMapCustomValueRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapCustomMessage{
		Items: map[uint32]mapCustomValue{
			1: {data: []byte{0xaa, 0xbb}},
			2: {data: []byte{0xcc}},
		},
	}

	limits := FieldLimits{"parties": 10, "field": 100}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapCustomMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.Items[1].data, []byte{0xaa, 0xbb}) {
		t.Fatalf("custom roundtrip mismatch: %v", decoded.Items[1].data)
	}
	if !bytes.Equal(decoded.Items[2].data, []byte{0xcc}) {
		t.Fatalf("custom roundtrip mismatch: %v", decoded.Items[2].data)
	}
}

func TestMapFixedLenValueRoundtrip(t *testing.T) {
	t.Parallel()

	orig := mapFixedLenMessage{
		Items: map[uint32][4]byte{
			1: {0x01, 0x02, 0x03, 0x04},
		},
	}

	limits := FieldLimits{"parties": 10}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapFixedLenMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}

	if decoded.Items[1] != [4]byte{0x01, 0x02, 0x03, 0x04} {
		t.Fatalf("got %v", decoded.Items[1])
	}
}

func TestMapFixedLenValueRejectsWrongLength(t *testing.T) {
	t.Parallel()

	limits := FieldLimits{"parties": 10}
	for _, value := range [][]byte{
		{0x01, 0x02, 0x03},
		{0x01, 0x02, 0x03, 0x04, 0x05},
	} {
		mapRaw := mapEncodeRawEntries(mapRawEntry{key: 1, value: value})
		raw, err := MarshalFields(1, "wire.test.map.fixedlen", []Field{{Tag: 1, Value: mapRaw}})
		if err != nil {
			t.Fatal(err)
		}
		var decoded mapFixedLenMessage
		if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err == nil {
			t.Fatalf("accepted map array value length %d", len(value))
		}
	}
}

func TestMapTrailingDataRejected(t *testing.T) {
	t.Parallel()

	// Construct a valid map body, then append trailing data.
	entries := mapEncodeRawEntries(
		mapRawEntry{key: 1, value: []byte{0x01}},
	)
	// Append an extra byte.
	entries = append(entries, 0xff)

	raw, err := MarshalFields(1, "wire.test.map.bytes", []Field{
		{Tag: 1, Value: entries},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	limits := FieldLimits{"parties": 10, "field": 100}
	err = Unmarshal(raw, &decoded, WithFieldLimits(limits))
	if err == nil {
		t.Fatal("expected error for trailing map data")
	}
}

func TestMapTruncatedKeyRejected(t *testing.T) {
	t.Parallel()

	// Construct a map body with count=1 but truncated key length prefix.
	// count=1 followed by only 1 byte of the required 4-byte key length prefix.
	body := Uint32(1)
	body = append(body, 0x00) // truncated: only 1 byte of key length (need 4)

	raw, err := MarshalFields(1, "wire.test.map.bytes", []Field{
		{Tag: 1, Value: body},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	limits := FieldLimits{"parties": 10, "field": 100}
	err = Unmarshal(raw, &decoded, WithFieldLimits(limits))
	if err == nil {
		t.Fatal("expected error for truncated map key")
	}
}

func TestMapTruncatedValueRejected(t *testing.T) {
	t.Parallel()

	// Count=1, valid key=0x00000001, value length=5 but only 2 bytes follow.
	body := Uint32(1)                           // count
	body = AppendBytes(body, Uint32(1))         // key=1
	body = append(body, 0x00, 0x00, 0x00, 0x05) // value length=5
	body = append(body, 0xaa, 0xbb)             // only 2 bytes

	raw, err := MarshalFields(1, "wire.test.map.bytes", []Field{
		{Tag: 1, Value: body},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapBytesMessage
	limits := FieldLimits{"parties": 10, "field": 100}
	err = Unmarshal(raw, &decoded, WithFieldLimits(limits))
	if err == nil {
		t.Fatal("expected error for truncated map value")
	}
}

func TestMapBigEndianKeyEncoding(t *testing.T) {
	t.Parallel()

	// Verify that keys are big-endian encoded by checking that key 0x01000000
	// sorts after key 0x0000ffff (because big-endian byte compare).
	orig := mapBytesMessage{
		Items: map[testPartyID][]byte{
			0x01000000: {0x01},
			0x0000ffff: {0x02},
		},
	}

	limits := FieldLimits{"parties": 10, "field": 100}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	// Extract keys from the encoded map.
	_, fields, err := UnmarshalFields(raw, "wire.test.map.bytes")
	if err != nil {
		t.Fatal(err)
	}

	mapRaw := fields[0].Value
	count, offset, err := ReadUint32(mapRaw, 0)
	if err != nil {
		t.Fatal(err)
	}

	var keys []uint32
	for i := 0; i < int(count); i++ {
		keyBytes, next, err := ReadBytes(mapRaw, offset)
		if err != nil {
			t.Fatal(err)
		}
		offset = next
		k, _ := DecodeUint32(keyBytes)
		keys = append(keys, k)
		// Skip value.
		_, offset, err = ReadBytes(mapRaw, offset)
		if err != nil {
			t.Fatal(err)
		}
	}

	// 0x0000ffff < 0x01000000 in big-endian byte order.
	if keys[0] != 0x0000ffff || keys[1] != 0x01000000 {
		t.Fatalf("big-endian key order wrong: %v", keys)
	}
}

func TestMapDirectUint32Key(t *testing.T) {
	t.Parallel()

	orig := mapU32Message{
		Items: map[uint32]uint32{5: 50, 3: 30, 7: 70},
	}

	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded mapU32Message
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(decoded.Items))
	}
	if decoded.Items[3] != 30 || decoded.Items[5] != 50 || decoded.Items[7] != 70 {
		t.Fatalf("got %v", decoded.Items)
	}
}

// ---- schema parse error tests ----

func TestMapUnsupportedKeyTypeRejected(t *testing.T) {
	t.Parallel()

	// map[int] is not supported.
	type badKeyMessage struct {
		Items map[int][]byte `wire:"1,map"`
	}
	// We can't even get to Marshal because the type doesn't implement Message,
	// but the schema construction should fail. However, the WireType/WireVersion
	// methods are required. Let's check that parseSchema catches it.
	_, err := getSchema(reflect.TypeFor[badKeyMessage]())
	if err == nil {
		t.Fatal("expected schema parse error for map[int] key")
	}
}

func TestMapUnsupportedValueTypeRejected(t *testing.T) {
	t.Parallel()

	// map[uint32][]uint32 is not supported.
	type badValueMessage struct {
		Items map[uint32][]uint32 `wire:"1,map"`
	}
	_, err := getSchema(reflect.TypeFor[badValueMessage]())
	if err == nil {
		t.Fatal("expected schema parse error for map[uint32][]uint32 value")
	}
}

func TestMapStringKeyRejected(t *testing.T) {
	t.Parallel()

	type stringKeyMessage struct {
		Items map[string][]byte `wire:"1,map"`
	}
	_, err := getSchema(reflect.TypeFor[stringKeyMessage]())
	if err == nil {
		t.Fatal("expected schema parse error for map[string] key")
	}
}

func TestMapUint64KeyRejected(t *testing.T) {
	t.Parallel()

	type uint64KeyMessage struct {
		Items map[uint64][]byte `wire:"1,map"`
	}
	_, err := getSchema(reflect.TypeFor[uint64KeyMessage]())
	if err == nil {
		t.Fatal("expected schema parse error for map[uint64] key")
	}
}
