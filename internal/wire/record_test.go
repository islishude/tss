package wire

import (
	"bytes"
	"reflect"
	"testing"
)

// ---- record test types -------------------------------------------------------

type innerRecord struct {
	Name string `wire:"1,max_bytes=name"`
	Data []byte `wire:"2,max_bytes=data"`
}

type recordMessage struct {
	Inner innerRecord `wire:"1"`
}

func (m recordMessage) WireType() string    { return "test.record" }
func (m recordMessage) WireVersion() uint16 { return 1 }

type explicitRecordMessage struct {
	Inner innerRecord `wire:"1,record"`
}

func (m explicitRecordMessage) WireType() string    { return "test.explicitrecord" }
func (m explicitRecordMessage) WireVersion() uint16 { return 1 }

type pointerRecordMessage struct {
	Inner *innerRecord `wire:"1"`
}

func (m pointerRecordMessage) WireType() string    { return "test.pointerrecord" }
func (m pointerRecordMessage) WireVersion() uint16 { return 1 }

type itemRecord struct {
	Key   string `wire:"1,max_bytes=key"`
	Value []byte `wire:"2,max_bytes=value"`
}

type recordListMessage struct {
	Items []itemRecord `wire:"1,max_items=items"`
}

func (m recordListMessage) WireType() string    { return "test.recordlist" }
func (m recordListMessage) WireVersion() uint16 { return 1 }

type explicitRecordListMessage struct {
	Items []itemRecord `wire:"1,recordlist,max_items=items"`
}

func (m explicitRecordListMessage) WireType() string    { return "test.explicitrecordlist" }
func (m explicitRecordListMessage) WireVersion() uint16 { return 1 }

type pointerRecordListMessage struct {
	Items []*itemRecord `wire:"1,max_items=items"`
}

func (m pointerRecordListMessage) WireType() string    { return "test.pointerrecordlist" }
func (m pointerRecordListMessage) WireVersion() uint16 { return 1 }

// recordWithHook implements validation hooks.
type recordWithHook struct {
	beforeCalled bool
	afterCalled  bool
	validated    bool
	Value        uint16 `wire:"1"`
}

func (r *recordWithHook) BeforeMarshalWire() error {
	r.beforeCalled = true
	return nil
}

func (r *recordWithHook) AfterUnmarshalWire() error {
	r.afterCalled = true
	return nil
}

func (r *recordWithHook) Validate() error {
	r.validated = true
	return nil
}

type hookRecordMessage struct {
	Rec recordWithHook `wire:"1"`
}

func (m hookRecordMessage) WireType() string    { return "test.hookrecord" }
func (m hookRecordMessage) WireVersion() uint16 { return 1 }

// ---- record round trip tests -------------------------------------------------

func TestRecordRoundTrip(t *testing.T) {
	t.Parallel()
	orig := recordMessage{
		Inner: innerRecord{
			Name: "test-name",
			Data: []byte{1, 2, 3},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	})); err != nil {
		t.Fatal(err)
	}

	if decoded.Inner.Name != orig.Inner.Name {
		t.Fatalf("Name: got %q, want %q", decoded.Inner.Name, orig.Inner.Name)
	}
	if !bytes.Equal(decoded.Inner.Data, orig.Inner.Data) {
		t.Fatalf("Data: got %v, want %v", decoded.Inner.Data, orig.Inner.Data)
	}
}

func TestRecordListRoundTrip(t *testing.T) {
	t.Parallel()
	orig := recordListMessage{
		Items: []itemRecord{
			{Key: "key1", Value: []byte{1, 2}},
			{Key: "key2", Value: []byte{3, 4, 5}},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"key":   32,
		"value": 1024,
		"items": 16,
	}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordListMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"key":   32,
		"value": 1024,
		"items": 16,
	})); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Items) != len(orig.Items) {
		t.Fatalf("got %d items, want %d", len(decoded.Items), len(orig.Items))
	}
	for i := range orig.Items {
		if decoded.Items[i].Key != orig.Items[i].Key {
			t.Fatalf("item %d Key: got %q, want %q", i, decoded.Items[i].Key, orig.Items[i].Key)
		}
		if !bytes.Equal(decoded.Items[i].Value, orig.Items[i].Value) {
			t.Fatalf("item %d Value: got %v, want %v", i, decoded.Items[i].Value, orig.Items[i].Value)
		}
	}
}

func TestRecordListNilSlice(t *testing.T) {
	t.Parallel()
	orig := recordListMessage{Items: nil}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{"items": 16}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordListMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"items": 16})); err != nil {
		t.Fatal(err)
	}
	// Nil or empty — both are acceptable.
	if len(decoded.Items) != 0 {
		t.Fatalf("expected empty slice, got %d items", len(decoded.Items))
	}
}

func TestRecordListEmptySlice(t *testing.T) {
	t.Parallel()
	orig := recordListMessage{Items: []itemRecord{}}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{"items": 16}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordListMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"items": 16})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Items) != 0 {
		t.Fatalf("expected empty slice, got %d items", len(decoded.Items))
	}
}

func TestRecordPointerRoundTrip(t *testing.T) {
	t.Parallel()
	orig := pointerRecordMessage{
		Inner: &innerRecord{
			Name: "ptr-test",
			Data: []byte{9, 8, 7},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded pointerRecordMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	})); err != nil {
		t.Fatal(err)
	}

	if decoded.Inner == nil {
		t.Fatal("expected non-nil pointer after decode")
	}
	if decoded.Inner.Name != orig.Inner.Name {
		t.Fatalf("Name: got %q, want %q", decoded.Inner.Name, orig.Inner.Name)
	}
}

func TestRecordListPointerRoundTrip(t *testing.T) {
	t.Parallel()
	orig := pointerRecordListMessage{
		Items: []*itemRecord{
			{Key: "a", Value: []byte{1}},
			{Key: "b", Value: []byte{2}},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"key":   32,
		"value": 1024,
		"items": 16,
	}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded pointerRecordListMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"key":   32,
		"value": 1024,
		"items": 16,
	})); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Items) != len(orig.Items) {
		t.Fatalf("got %d items, want %d", len(decoded.Items), len(orig.Items))
	}
	for i := range orig.Items {
		if decoded.Items[i] == nil {
			t.Fatalf("item %d is nil", i)
		}
		if decoded.Items[i].Key != orig.Items[i].Key {
			t.Fatalf("item %d Key mismatch", i)
		}
	}
}

// ---- record max_items tests --------------------------------------------------

func TestRecordListMaxItemsExceededEncode(t *testing.T) {
	t.Parallel()
	orig := recordListMessage{
		Items: make([]itemRecord, 5),
	}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"items": 3, // cap at 3
	}))
	if err == nil {
		t.Fatal("expected error for exceeding max_items during encode")
	}
}

func TestRecordListMaxItemsExceededDecode(t *testing.T) {
	t.Parallel()
	// Build a recordlist with 4 items bypassing the encoder's max_items check.
	var records []byte
	records = append(records, Uint32(4)...) // count=4
	for i := range 4 {
		body, _ := marshalFieldBody([]Field{
			{Tag: 1, Value: []byte{byte('a' + i)}}, // Key
			{Tag: 2, Value: []byte{}},              // Value
		})
		records = append(records, Uint32(uint32(len(body)))...)
		records = append(records, body...)
	}

	fields := []Field{
		{Tag: 1, Value: records},
	}
	raw, err := MarshalFields(1, "test.recordlist", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordListMessage
	err = Unmarshal(raw, &decoded, WithFrameLimits(FrameLimits{
		MaxTotalBytes: 1 << 20,
		MaxFields:     256,
		MaxFieldBytes: 1 << 20,
	}), WithFieldLimits(FieldLimits{
		"items": 3, // cap at 3
		"key":   32,
		"value": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for exceeding max_items during decode")
	}
}

// ---- record strict field set tests --------------------------------------------

func TestRecordMissingFieldRejected(t *testing.T) {
	t.Parallel()
	// Build a field body with only tag 1, missing tag 2.
	body, err := marshalFieldBody([]Field{
		{Tag: 1, Value: []byte("only-one-field")},
	})
	if err != nil {
		t.Fatal(err)
	}

	fields := []Field{
		{Tag: 1, Value: body},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for missing field in record")
	}
}

func TestRecordExtraFieldRejected(t *testing.T) {
	t.Parallel()
	// Build a field body with an extra tag.
	body, err := marshalFieldBody([]Field{
		{Tag: 1, Value: []byte("name")},
		{Tag: 2, Value: []byte{}},
		{Tag: 99, Value: []byte("extra")},
	})
	if err != nil {
		t.Fatal(err)
	}

	fields := []Field{
		{Tag: 1, Value: body},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for extra field in record")
	}
}

func TestRecordUnsortedTagsRejected(t *testing.T) {
	t.Parallel()
	// Manually encode fields in wrong tag order (tag 2 before tag 1).
	value := make([]byte, 0)
	value = AppendUint16(value, 2)                   // field count
	value = AppendUint16(value, 2)                   // tag 2 (wrong order)
	value = AppendUint32(value, 0)                   // length 0
	value = AppendUint16(value, 1)                   // tag 1
	value = AppendUint32(value, uint32(len("name"))) // length
	value = append(value, "name"...)

	fields := []Field{
		{Tag: 1, Value: value},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for unsorted tags in record")
	}
}

func TestRecordDuplicateTagRejected(t *testing.T) {
	t.Parallel()
	// Manually encode duplicate tag.
	value := make([]byte, 0)
	value = AppendUint16(value, 2) // field count
	value = AppendUint16(value, 1) // tag 1
	value = AppendUint32(value, uint32(len("name1")))
	value = append(value, "name1"...)
	value = AppendUint16(value, 1) // tag 1 again (duplicate)
	value = AppendUint32(value, 0)

	fields := []Field{
		{Tag: 1, Value: value},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for duplicate tag in record")
	}
}

func TestRecordTrailingBytesRejected(t *testing.T) {
	t.Parallel()
	// Build a valid field body, then append extra bytes.
	body, err := marshalFieldBody([]Field{
		{Tag: 1, Value: []byte("name")},
		{Tag: 2, Value: []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, 0x00) // trailing byte

	fields := []Field{
		{Tag: 1, Value: body},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	// Should fail either at the record trailing bytes check or at the envelope trailing bytes check.
	if err == nil {
		t.Fatal("expected error for trailing bytes in record or envelope")
	}
}

// ---- record hooks tests -------------------------------------------------------

func TestRecordHooksCalled(t *testing.T) {
	t.Parallel()
	orig := hookRecordMessage{
		Rec: recordWithHook{Value: 42},
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// The original's hooks should have been called during marshal.
	// Note: Marshal works on a copy, so we need to check the encoded message still works.

	var decoded hookRecordMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Rec.Value != 42 {
		t.Fatalf("Value: got %d, want 42", decoded.Rec.Value)
	}
	if !decoded.Rec.afterCalled {
		t.Error("AfterUnmarshalWire was not called on decoded record")
	}
	if !decoded.Rec.validated {
		t.Error("Validate was not called on decoded record")
	}
}

// ---- record max_bytes tests ---------------------------------------------------

func TestRecordMaxBytesExceededEncode(t *testing.T) {
	t.Parallel()
	orig := recordMessage{
		Inner: innerRecord{
			Name: "this-name-is-way-too-long-for-the-limit",
			Data: []byte{1},
		},
	}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"name": 5, // cap at 5 bytes
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for exceeding max_bytes in record field during encode")
	}
}

func TestRecordBytesMaxBytesExceededEncode(t *testing.T) {
	t.Parallel()
	orig := recordMessage{
		Inner: innerRecord{
			Name: "ok",
			Data: []byte{1, 2, 3, 4},
		},
	}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"name": 32,
		"data": 3,
	}))
	if err == nil {
		t.Fatal("expected error for exceeding max_bytes on record bytes field during encode")
	}
}

func TestRecordMaxBytesExceededDecode(t *testing.T) {
	t.Parallel()
	body, err := marshalFieldBody([]Field{
		{Tag: 1, Value: []byte("too-long")},
		{Tag: 2, Value: []byte{}},
	})
	if err != nil {
		t.Fatal(err)
	}

	fields := []Field{
		{Tag: 1, Value: body},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 3, // cap at 3 bytes
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for exceeding max_bytes in record field during decode")
	}
}

// ---- non-UTF-8 string in record test ------------------------------------------

func TestRecordNonUTF8StringRejected(t *testing.T) {
	t.Parallel()
	nonUTF8 := []byte{0xff, 0xfe, 0xfd}
	body, err := marshalFieldBody([]Field{
		{Tag: 1, Value: nonUTF8}, // Name as invalid UTF-8
		{Tag: 2, Value: []byte{}},
	})
	if err != nil {
		t.Fatal(err)
	}

	fields := []Field{
		{Tag: 1, Value: body},
	}
	raw, err := MarshalFields(1, "test.record", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded recordMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for non-UTF-8 string in record")
	}
}

// ---- nil pointer record encode test -------------------------------------------

func TestNilRecordPointerEncodeRejected(t *testing.T) {
	t.Parallel()
	orig := pointerRecordMessage{Inner: nil}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{
		"name": 32,
		"data": 1024,
	}))
	if err == nil {
		t.Fatal("expected error for nil record pointer")
	}
}

// ---- schema parse test --------------------------------------------------------

func TestRecordSchemaParse(t *testing.T) {
	t.Parallel()
	// Verify that the schema parser correctly infers record and recordlist kinds.
	s, err := getSchema(reflect.TypeFor[recordMessage]())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(s.fields))
	}
	if s.fields[0].kind != kindRecord {
		t.Fatalf("expected kindRecord, got %d", s.fields[0].kind)
	}

	s2, err := getSchema(reflect.TypeFor[recordListMessage]())
	if err != nil {
		t.Fatal(err)
	}
	if s2.fields[0].kind != kindRecordList {
		t.Fatalf("expected kindRecordList, got %d", s2.fields[0].kind)
	}

	s3, err := getSchema(reflect.TypeFor[explicitRecordMessage]())
	if err != nil {
		t.Fatal(err)
	}
	if s3.fields[0].kind != kindRecord {
		t.Fatalf("expected explicit kindRecord, got %d", s3.fields[0].kind)
	}

	s4, err := getSchema(reflect.TypeFor[explicitRecordListMessage]())
	if err != nil {
		t.Fatal(err)
	}
	if s4.fields[0].kind != kindRecordList {
		t.Fatalf("expected explicit kindRecordList, got %d", s4.fields[0].kind)
	}
}
