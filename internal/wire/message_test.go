package wire

import (
	"bytes"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

// testFieldLimits returns generous field limits for all semantic names used by
// test message types. Fail-closed wire enforcement requires FieldLimits whenever
// a struct tag references max_bytes=name or max_items=name.
func testFieldLimits() FieldLimits {
	return FieldLimits{
		"field": 1000,
		"name":  1000,
		"items": 100,
		"ids":   100,
		"data":  1000,
	}
}

// ---- test message types -----------------------------------------------------

type simpleMessage struct {
	Name  string `wire:"1,string"`
	Count uint32 `wire:"2,u32"`
	Data  []byte `wire:"3,bytes"`
}

func (m simpleMessage) WireType() string    { return "test.simple" }
func (m simpleMessage) WireVersion() uint16 { return 1 }

type ptrMethodMessage struct {
	Value uint16 `wire:"1,u16"`
}

func (m *ptrMethodMessage) WireType() string    { return "test.ptrmethod" }
func (m *ptrMethodMessage) WireVersion() uint16 { return 2 }

type fixedLenMessage struct {
	Hash []byte `wire:"1,bytes,len=32"`
}

func (m fixedLenMessage) WireType() string    { return "test.fixedlen" }
func (m fixedLenMessage) WireVersion() uint16 { return 1 }

type boolMessage struct {
	Flag bool `wire:"1,bool"`
}

func (m boolMessage) WireType() string    { return "test.bool" }
func (m boolMessage) WireVersion() uint16 { return 1 }

type maxBytesMessage struct {
	Payload []byte `wire:"1,bytes,max_bytes=field"`
}

func (m maxBytesMessage) WireType() string    { return "test.maxbytes" }
func (m maxBytesMessage) WireVersion() uint16 { return 1 }

type u32ListMessage struct {
	IDs []uint32 `wire:"1,u32list,max_items=ids"`
}

func (m u32ListMessage) WireType() string    { return "test.u32list" }
func (m u32ListMessage) WireVersion() uint16 { return 1 }

type bytesListMessage struct {
	Items [][]byte `wire:"1,byteslist,max_bytes=field,max_items=items"`
}

func (m bytesListMessage) WireType() string    { return "test.byteslist" }
func (m bytesListMessage) WireVersion() uint16 { return 1 }

type partyBytesMessage struct {
	Records []PartyBytes[uint32] `wire:"1,partybytes,max_bytes=field"`
}

func (m partyBytesMessage) WireType() string    { return "test.partybytes" }
func (m partyBytesMessage) WireVersion() uint16 { return 1 }

type partyBytePairsMessage struct {
	Pairs []PartyBytePair[uint32] `wire:"1,partybytepairs,max_bytes=field"`
}

func (m partyBytePairsMessage) WireType() string    { return "test.partybytepairs" }
func (m partyBytePairsMessage) WireVersion() uint16 { return 1 }

type nestedMessage struct {
	Inner simpleMessage `wire:"1,nested"`
	Tag   uint8         `wire:"2,u8"`
}

func (m nestedMessage) WireType() string    { return "test.nested" }
func (m nestedMessage) WireVersion() uint16 { return 1 }

type validatedMessage struct {
	Value []byte `wire:"1,bytes"`
	ok    bool
}

func (m validatedMessage) WireType() string    { return "test.validated" }
func (m validatedMessage) WireVersion() uint16 { return 1 }
func (m *validatedMessage) Validate() error {
	if m.ok {
		return nil
	}
	return errSentinel
}

type hookMessage struct {
	BeforeCalled bool
	AfterCalled  bool
	Value        uint16 `wire:"1,u16"`
}

func (m hookMessage) WireType() string    { return "test.hooks" }
func (m hookMessage) WireVersion() uint16 { return 1 }
func (m *hookMessage) BeforeMarshalWire() error {
	m.BeforeCalled = true
	return nil
}
func (m *hookMessage) AfterUnmarshalWire() error {
	m.AfterCalled = true
	return nil
}

type emptyBytesMessage struct {
	Data []byte `wire:"1,bytes,allow_empty"`
}

func (m emptyBytesMessage) WireType() string    { return "test.emptybytes" }
func (m emptyBytesMessage) WireVersion() uint16 { return 1 }

// ---- kind inference test types -----------------------------------------------

// inferredMessage uses tag-only form (no explicit kind).
type inferredMessage struct {
	Name  string `wire:"1"`
	Count uint32 `wire:"2"`
	Data  []byte `wire:"3"`
}

func (m inferredMessage) WireType() string    { return "test.inferred" }
func (m inferredMessage) WireVersion() uint16 { return 1 }

type namedString string
type namedU32 uint32

// namedInferredMessage tests named primitive type inference.
type namedInferredMessage struct {
	S namedString `wire:"1"`
	N namedU32    `wire:"2"`
}

func (m namedInferredMessage) WireType() string    { return "test.namedinferred" }
func (m namedInferredMessage) WireVersion() uint16 { return 1 }

// inferredWithOptionsMessage tests tag-only form with options.
type inferredWithOptionsMessage struct {
	Hash []byte `wire:"1,len=32"`
	Name string `wire:"2,max_bytes=name"`
}

func (m inferredWithOptionsMessage) WireType() string    { return "test.inferredopts" }
func (m inferredWithOptionsMessage) WireVersion() uint16 { return 1 }

// stringLimitMessage tests max_bytes and len on string fields.
type stringLimitMessage struct {
	Name string `wire:"1,string,max_bytes=name"`
	Code string `wire:"2,string,len=4"`
}

func (m stringLimitMessage) WireType() string    { return "test.stringlimit" }
func (m stringLimitMessage) WireVersion() uint16 { return 1 }

// stringLimitInferredMessage tests max_bytes on inferred string fields.
type stringLimitInferredMessage struct {
	Name string `wire:"1,max_bytes=name"`
}

func (m stringLimitInferredMessage) WireType() string    { return "test.stringlimitinf" }
func (m stringLimitInferredMessage) WireVersion() uint16 { return 1 }

// ---- sentinel error for validation tests ------------------------------------

var errSentinel = &testError{"sentinel"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ---- tests ------------------------------------------------------------------

func TestCodecMarshalRoundTrip(t *testing.T) {
	orig := simpleMessage{
		Name:  "hello",
		Count: 42,
		Data:  []byte{1, 2, 3},
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded simpleMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != orig.Name || decoded.Count != orig.Count || !bytes.Equal(decoded.Data, orig.Data) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestMarshalRoundTripPointer(t *testing.T) {
	orig := &simpleMessage{
		Name:  "world",
		Count: 99,
		Data:  []byte{4, 5, 6},
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded simpleMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != orig.Name || decoded.Count != orig.Count || !bytes.Equal(decoded.Data, orig.Data) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestMarshalPointerReceiverMethods(t *testing.T) {
	// Message implemented on *ptrMethodMessage — must work with Marshal(&m)
	orig := &ptrMethodMessage{Value: 7}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ptrMethodMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Value != 7 {
		t.Fatalf("got %d, want 7", decoded.Value)
	}
}

func TestMarshalCanonicalRemarshal(t *testing.T) {
	orig := simpleMessage{Name: "x", Count: 1, Data: []byte{0xff}}
	raw1, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("marshal is not deterministic")
	}
}

func TestMarshalNilBytesEncodesEmpty(t *testing.T) {
	orig := emptyBytesMessage{Data: nil}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded emptyBytesMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	// nil and empty slices both round-trip successfully.
	_ = decoded.Data
}

func TestUnmarshalWrongTypeID(t *testing.T) {
	orig := simpleMessage{Name: "x", Count: 1}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper type id to refer to a different message type.
	var dst ptrMethodMessage
	if err := Unmarshal(raw, &dst); err == nil {
		t.Fatal("expected error for wrong type id")
	}
}

func TestUnmarshalWrongVersion(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: Uint16(99)},
	}
	raw, err := MarshalFields(99, "test.ptrmethod", fields)
	if err != nil {
		t.Fatal(err)
	}
	var dst ptrMethodMessage
	if err := Unmarshal(raw, &dst); err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestUnmarshalMissingField(t *testing.T) {
	// Construct a message with only tag 1, missing tag 2 and 3.
	fields := []Field{
		{Tag: 1, Value: []byte("x")},
	}
	raw, err := MarshalFields(1, "test.simple", fields)
	if err != nil {
		t.Fatal(err)
	}
	var dst simpleMessage
	if err := Unmarshal(raw, &dst); err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestUnmarshalExtraField(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte("x")},
		{Tag: 2, Value: Uint32(1)},
		{Tag: 3, Value: []byte{}},
		{Tag: 99, Value: []byte("extra")},
	}
	raw, err := MarshalFields(1, "test.simple", fields)
	if err != nil {
		t.Fatal(err)
	}
	var dst simpleMessage
	if err := Unmarshal(raw, &dst); err == nil {
		t.Fatal("expected error for extra field")
	}
}

func TestUnmarshalRejectsNilDst(t *testing.T) {
	var dst *simpleMessage
	if err := Unmarshal([]byte("junk"), dst); err == nil {
		t.Fatal("expected error for nil dst")
	}
}

func TestMarshalRejectsNilPointer(t *testing.T) {
	var m *simpleMessage
	if _, err := Marshal(m); err == nil {
		t.Fatal("expected error for nil pointer")
	}
}

func TestMarshalRejectsNonStruct(t *testing.T) {
	if _, err := Marshal(42); err == nil {
		t.Fatal("expected error for int")
	}
}

func TestUnmarshalRejectsNonPointer(t *testing.T) {
	var dst simpleMessage
	if err := Unmarshal(nil, dst); err == nil {
		t.Fatal("expected error for non-pointer dst")
	}
}

func TestFixedLenEnforced(t *testing.T) {
	orig := fixedLenMessage{Hash: make([]byte, 32)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded fixedLenMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestFixedLenRejected(t *testing.T) {
	orig := fixedLenMessage{Hash: make([]byte, 31)}
	if _, err := Marshal(orig); err != nil {
		t.Fatal("marshal should not reject wrong length (only unmarshal)")
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Wait, actually the `len` check is decode-time. Let me verify —
	// The plan says fixedLen is checked on decode via checkFixedLen.
	var decoded fixedLenMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for wrong fixed length on decode") // 31 != 32
	}
}

func TestBoolEncodeDecode(t *testing.T) {
	for _, v := range []bool{true, false} {
		orig := boolMessage{Flag: v}
		raw, err := Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var decoded boolMessage
		if err := Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Flag != v {
			t.Fatalf("bool: got %v, want %v", decoded.Flag, v)
		}
	}
}

func TestMaxBytesEnforcedDecode(t *testing.T) {
	orig := maxBytesMessage{Payload: []byte("hello")}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Decode with a limit that is too small.
	var decoded maxBytesMessage
	err = Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 3}))
	if err == nil {
		t.Fatal("expected error for exceeding max_bytes")
	}
}

func TestMaxBytesOkWhenUnderLimit(t *testing.T) {
	orig := maxBytesMessage{Payload: []byte("hi")}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded maxBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 10})); err != nil {
		t.Fatal(err)
	}
}

func TestCodecU32List(t *testing.T) {
	orig := u32ListMessage{IDs: []uint32{1, 2, 3}}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded u32ListMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"ids": 10})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.IDs) != 3 || decoded.IDs[0] != 1 || decoded.IDs[2] != 3 {
		t.Fatalf("u32list mismatch: %v", decoded.IDs)
	}
}

func TestU32ListMaxItems(t *testing.T) {
	orig := u32ListMessage{IDs: []uint32{1, 2, 3, 4, 5}}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded u32ListMessage
	err = Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"ids": 3}))
	if err == nil {
		t.Fatal("expected error for too many items")
	}
}

func TestCodecBytesList(t *testing.T) {
	orig := bytesListMessage{Items: [][]byte{{1, 2}, {3, 4, 5}}}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded bytesListMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 100, "items": 10})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Items) != 2 || !bytes.Equal(decoded.Items[1], []byte{3, 4, 5}) {
		t.Fatalf("byteslist mismatch: %v", decoded.Items)
	}
}

func TestPartyBytesEncodeDecode(t *testing.T) {
	orig := partyBytesMessage{
		Records: []PartyBytes[uint32]{
			{Party: 1, Bytes: []byte("aaa")},
			{Party: 3, Bytes: []byte("bbb")},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded partyBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 100})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 2 {
		t.Fatalf("partybytes count: %d", len(decoded.Records))
	}
	if decoded.Records[0].Party != 1 || !bytes.Equal(decoded.Records[0].Bytes, []byte("aaa")) {
		t.Fatalf("partybytes[0]: party=%d bytes=%x", decoded.Records[0].Party, decoded.Records[0].Bytes)
	}
}

func TestPartyBytePairsEncodeDecode(t *testing.T) {
	orig := partyBytePairsMessage{
		Pairs: []PartyBytePair[uint32]{
			{Party: 1, First: []byte{1}, Second: []byte{2}},
			{Party: 2, First: []byte{3}, Second: []byte{4}},
		},
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded partyBytePairsMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 100})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Pairs) != 2 {
		t.Fatalf("partybytepairs count: %d", len(decoded.Pairs))
	}
	if !bytes.Equal(decoded.Pairs[1].First, []byte{3}) {
		t.Fatalf("partybytepairs[1].First: %x", decoded.Pairs[1].First)
	}
}

func TestNestedEncodeDecode(t *testing.T) {
	orig := nestedMessage{
		Inner: simpleMessage{Name: "nested", Count: 7, Data: []byte{9}},
		Tag:   42,
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded nestedMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Inner.Name != "nested" || decoded.Inner.Count != 7 || decoded.Tag != 42 {
		t.Fatalf("nested mismatch: %+v", decoded)
	}
}

func TestValidateCalledOnMarshal(t *testing.T) {
	m := validatedMessage{Value: []byte{1}, ok: false} // invalid
	if _, err := Marshal(&m); err == nil {
		t.Fatal("expected validation error on marshal")
	}
	m.ok = true
	if _, err := Marshal(&m); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateCalledOnUnmarshal(t *testing.T) {
	// Marshal a valid message.
	m := validatedMessage{Value: []byte{1}, ok: true}
	raw, err := Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	// validatedMessage.Validate checks m.ok, which defaults to false.
	var decoded validatedMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected validation error on unmarshal")
	}
}

func TestHooksCalled(t *testing.T) {
	m := hookMessage{Value: 5}
	raw, err := Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	if !m.BeforeCalled {
		t.Fatal("BeforeMarshalWire not called")
	}

	var decoded hookMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.AfterCalled {
		t.Fatal("AfterUnmarshalWire not called")
	}
	if decoded.Value != 5 {
		t.Fatalf("value mismatch: %d", decoded.Value)
	}
}

func TestInvalidUTF8StringRejected(t *testing.T) {
	// Build raw bytes with invalid UTF-8 for a string field.
	fields := []Field{
		{Tag: 1, Value: []byte{0xff, 0xfe, 0xfd}}, // invalid UTF-8
		{Tag: 2, Value: Uint32(1)},
		{Tag: 3, Value: []byte{}},
	}
	raw, err := MarshalFields(1, "test.simple", fields)
	if err != nil {
		t.Fatal(err)
	}
	var dst simpleMessage
	if err := Unmarshal(raw, &dst); err == nil {
		t.Fatal("expected error for invalid UTF-8 string")
	}
}

func TestMissingLimitNameError(t *testing.T) {
	orig := maxBytesMessage{Payload: []byte("hi")}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Tag references "field" but the LimitSet does not contain it.
	var decoded maxBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"other": 100})); err == nil {
		t.Fatal("expected error for missing limit name")
	}
}

func TestMalformedU8(t *testing.T) {
	raw := []byte{0xff, 0xff} // 2 bytes for u8
	fields := []Field{
		{Tag: 1, Value: raw},
	}
	b, err := MarshalFields(1, "test.nested", fields)
	if err != nil {
		t.Fatal(err)
	}
	var dst nestedMessage
	if err := Unmarshal(b, &dst); err == nil {
		t.Fatal("expected error for malformed u8")
	}
}

func TestNilBytesListRoundTrip(t *testing.T) {
	orig := bytesListMessage{Items: nil}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded bytesListMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 100, "items": 10})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Items) != 0 {
		t.Fatalf("nil byteslist round-trip: got %d items", len(decoded.Items))
	}
}

func TestEmptyPartyBytesRoundTrip(t *testing.T) {
	orig := partyBytesMessage{}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded partyBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 100})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 0 {
		t.Fatalf("empty partybytes: got %d records", len(decoded.Records))
	}
}

func TestUnmarshalInvalidUTF8String(t *testing.T) {
	// Directly inject raw bytes that are not UTF-8.
	fields := []Field{
		{Tag: 1, Value: []byte{0x80}}, // continuation byte alone
		{Tag: 2, Value: Uint32(0)},
		{Tag: 3, Value: []byte{}},
	}
	raw, err := MarshalFields(1, "test.simple", fields)
	if err != nil {
		t.Fatal(err)
	}
	var dst simpleMessage
	if err := Unmarshal(raw, &dst); err == nil {
		t.Fatal("should reject invalid UTF-8 in string field")
	}
}

func TestMessageWireTypeAndVersion(t *testing.T) {
	// Ensure interface assertions work.
	var m Message = &ptrMethodMessage{}
	if m.WireType() != "test.ptrmethod" || m.WireVersion() != 2 {
		t.Fatalf("Message: type=%s version=%d", m.WireType(), m.WireVersion())
	}
}

// ---- custom field test types -------------------------------------------------

// customBytes is a simple domain type with value-receiver methods.
type customBytes struct {
	raw []byte
}

func (c customBytes) MarshalWireValue() ([]byte, error) {
	if c.raw == nil {
		return nil, errSentinel
	}
	out := make([]byte, len(c.raw))
	copy(out, c.raw)
	return out, nil
}

func (c *customBytes) UnmarshalWireValue(in []byte) error {
	if len(in) == 0 {
		return errSentinel
	}
	c.raw = make([]byte, len(in))
	copy(c.raw, in)
	return nil
}

// customPtrBytes is a domain type with pointer-receiver methods.
type customPtrBytes struct {
	raw []byte
}

func (c *customPtrBytes) MarshalWireValue() ([]byte, error) {
	if c == nil {
		return nil, errSentinel
	}
	out := make([]byte, len(c.raw))
	copy(out, c.raw)
	return out, nil
}

func (c *customPtrBytes) UnmarshalWireValue(in []byte) error {
	if c == nil {
		return errSentinel
	}
	c.raw = make([]byte, len(in))
	copy(c.raw, in)
	return nil
}

// customNoUnmarshal implements MarshalWireValue but NOT UnmarshalWireValue.
type customNoUnmarshal struct {
	raw []byte
}

func (c customNoUnmarshal) MarshalWireValue() ([]byte, error) {
	return c.raw, nil
}

// customNoMarshal implements UnmarshalWireValue but NOT MarshalWireValue.
type customNoMarshal struct {
	raw []byte
}

func (c *customNoMarshal) UnmarshalWireValue(in []byte) error {
	c.raw = make([]byte, len(in))
	copy(c.raw, in)
	return nil
}

// customNilReturn returns nil from MarshalWireValue.
type customNilReturn struct{}

func (c customNilReturn) MarshalWireValue() ([]byte, error) {
	return nil, nil
}

func (c *customNilReturn) UnmarshalWireValue(in []byte) error {
	return nil
}

// ---- custom field test messages ----------------------------------------------

type customValueReceiverMessage struct {
	Data customBytes `wire:"1,custom"`
}

func (m customValueReceiverMessage) WireType() string    { return "test.custom.valrecv" }
func (m customValueReceiverMessage) WireVersion() uint16 { return 1 }

type customPointerReceiverMessage struct {
	Data customPtrBytes `wire:"1,custom"`
}

func (m customPointerReceiverMessage) WireType() string    { return "test.custom.ptrrecv" }
func (m customPointerReceiverMessage) WireVersion() uint16 { return 1 }

type customPointerFieldMessage struct {
	Data *customBytes `wire:"1,custom,len=4"`
}

func (m customPointerFieldMessage) WireType() string    { return "test.custom.ptrfield" }
func (m customPointerFieldMessage) WireVersion() uint16 { return 1 }

type customFixedLenMessage struct {
	Data customBytes `wire:"1,custom,len=32"`
}

func (m customFixedLenMessage) WireType() string    { return "test.custom.fixedlen" }
func (m customFixedLenMessage) WireVersion() uint16 { return 1 }

type customMaxBytesMessage struct {
	Data customBytes `wire:"1,custom,max_bytes=field"`
}

func (m customMaxBytesMessage) WireType() string    { return "test.custom.maxbytes" }
func (m customMaxBytesMessage) WireVersion() uint16 { return 1 }

type customNoUnmarshalMessage struct {
	Data customNoUnmarshal `wire:"1,custom"`
}

func (m customNoUnmarshalMessage) WireType() string    { return "test.custom.nounmarshal" }
func (m customNoUnmarshalMessage) WireVersion() uint16 { return 1 }

type customNoMarshalMessage struct {
	Data customNoMarshal `wire:"1,custom"`
}

func (m customNoMarshalMessage) WireType() string    { return "test.custom.nomarshal" }
func (m customNoMarshalMessage) WireVersion() uint16 { return 1 }

type customNilReturnMessage struct {
	Data customNilReturn `wire:"1,custom"`
}

func (m customNilReturnMessage) WireType() string    { return "test.custom.nilreturn" }
func (m customNilReturnMessage) WireVersion() uint16 { return 1 }

type customMultiFieldMessage struct {
	First  customBytes `wire:"1,custom"`
	Second uint32      `wire:"2,u32"`
}

func (m customMultiFieldMessage) WireType() string    { return "test.custom.multifield" }
func (m customMultiFieldMessage) WireVersion() uint16 { return 1 }

// ---- custom field tests ------------------------------------------------------

func TestCustomRoundTripValueReceiver(t *testing.T) {
	orig := customValueReceiverMessage{
		Data: customBytes{raw: []byte{1, 2, 3, 4}},
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded customValueReceiverMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Data.raw, []byte{1, 2, 3, 4}) {
		t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
	}
}

func TestCustomRoundTripPointerReceiver(t *testing.T) {
	orig := customPointerReceiverMessage{
		Data: customPtrBytes{raw: []byte{5, 6, 7, 8}},
	}
	raw, err := Marshal(&orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded customPointerReceiverMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Data.raw, []byte{5, 6, 7, 8}) {
		t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
	}
}

func TestCustomPointerFieldAutoAlloc(t *testing.T) {
	orig := customPointerFieldMessage{
		Data: &customBytes{raw: []byte{9, 9, 9, 9}},
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal into a nil pointer field — codec must auto-allocate.
	var decoded customPointerFieldMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Data == nil {
		t.Fatal("pointer field was not auto-allocated")
	}
	if !bytes.Equal(decoded.Data.raw, []byte{9, 9, 9, 9}) {
		t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
	}
}

func TestCustomNilPointerMarshalFails(t *testing.T) {
	orig := customPointerFieldMessage{Data: nil}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for nil custom pointer field")
	}
}

func TestCustomMissingMarshalWireValue(t *testing.T) {
	// customNoMarshalMessage.Data does not implement MarshalWireValue.
	// But we can still try to marshal it — should fail.
	orig := customNoMarshalMessage{}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for missing MarshalWireValue")
	}
}

func TestCustomMissingUnmarshalWireValue(t *testing.T) {
	// customNoUnmarshalMessage.Data does not implement UnmarshalWireValue.
	// Marshal should work, but unmarshal should fail.
	orig := customNoUnmarshalMessage{Data: customNoUnmarshal{raw: []byte{1}}}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customNoUnmarshalMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for missing UnmarshalWireValue")
	}
}

func TestCustomMarshalWireValueReturnsNil(t *testing.T) {
	orig := customNilReturnMessage{}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for MarshalWireValue returning nil")
	}
}

func TestCustomFixedLenEnforced(t *testing.T) {
	// Marshal with correct length.
	orig := customFixedLenMessage{Data: customBytes{raw: make([]byte, 32)}}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customFixedLenMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	// Unmarshal with wrong length should fail.
	// Marshal a message with wrong length by bypassing object-level Marshal.
	fields := []Field{
		{Tag: 1, Value: make([]byte, 16)}, // len=32 expected
	}
	raw, err = MarshalFields(1, "test.custom.fixedlen", fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for wrong fixed length on custom field")
	}
}

func TestCustomMaxBytesEnforced(t *testing.T) {
	orig := customMaxBytesMessage{Data: customBytes{raw: []byte("hello")}}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	// Decode with a limit that is too small.
	var decoded customMaxBytesMessage
	err = Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 3}))
	if err == nil {
		t.Fatal("expected error for exceeding max_bytes on custom field")
	}

	// Should succeed with adequate limit.
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"field": 10})); err != nil {
		t.Fatal(err)
	}
}

func TestCustomMaxBytesNamedLimitMissing(t *testing.T) {
	orig := customMaxBytesMessage{Data: customBytes{raw: []byte("hi")}}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	// Tag references "field" but LimitSet does not contain it.
	var decoded customMaxBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithFieldLimits(FieldLimits{"other": 100})); err == nil {
		t.Fatal("expected error for missing named limit on custom field")
	}
}

func TestCustomValueWithPointerReceiver(t *testing.T) {
	// customPtrBytes has pointer-receiver methods.
	// A non-pointer struct field should still work via CanAddr()
	// when the parent message is passed by pointer.
	orig := customPointerReceiverMessage{
		Data: customPtrBytes{raw: []byte{10, 20}},
	}
	raw, err := Marshal(&orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customPointerReceiverMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Data.raw, []byte{10, 20}) {
		t.Fatalf("round-trip mismatch: got %x", decoded.Data.raw)
	}
}

func TestCustomErrorWrapping(t *testing.T) {
	// Trigger an error in UnmarshalWireValue by passing empty bytes
	// to customBytes (which rejects empty input with errSentinel).
	fields := []Field{
		{Tag: 1, Value: []byte{}},
		{Tag: 2, Value: Uint32(0)},
	}
	raw, err := MarshalFields(1, "test.custom.multifield", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customMultiFieldMessage
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	// Error should mention field name and tag.
	if !strings.Contains(err.Error(), "First") || !strings.Contains(err.Error(), "tag 1") {
		t.Fatalf("error should mention field name and tag: %v", err)
	}
}

func TestCustomFieldOrdering(t *testing.T) {
	orig := customMultiFieldMessage{
		First:  customBytes{raw: []byte{1, 2}},
		Second: 42,
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customMultiFieldMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.First.raw, []byte{1, 2}) || decoded.Second != 42 {
		t.Fatalf("field ordering broken: First=%x Second=%d", decoded.First.raw, decoded.Second)
	}
}

func TestCustomExactTagSet(t *testing.T) {
	// Extra tag should be rejected.
	fields := []Field{
		{Tag: 1, Value: []byte{1}},
		{Tag: 2, Value: Uint32(42)},
		{Tag: 3, Value: []byte("extra")}, // not in schema
	}
	raw, err := MarshalFields(1, "test.custom.multifield", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded customMultiFieldMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for extra field in custom message")
	}

	// Missing tag should be rejected.
	fields = []Field{
		{Tag: 1, Value: []byte{1}},
	}
	raw, err = MarshalFields(1, "test.custom.multifield", fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for missing field in custom message")
	}
}

func FuzzCustomField(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, in []byte) {
		// Construct a field with arbitrary bytes.
		fields := []Field{
			{Tag: 1, Value: in},
		}
		raw, err := MarshalFields(1, "test.custom.valrecv", fields)
		if err != nil {
			t.Fatal(err)
		}
		var decoded customValueReceiverMessage
		// Unmarshal should either succeed or return a clean error — no panic.
		_ = Unmarshal(raw, &decoded)
	})
}

// ---- big integer test types --------------------------------------------------

type bigIntSignedMessage struct {
	Val *big.Int `wire:"1,bigint"`
}

func (m bigIntSignedMessage) WireType() string    { return "test.bigint.signed" }
func (m bigIntSignedMessage) WireVersion() uint16 { return 1 }

type bigUintMessage struct {
	Val *big.Int `wire:"1,biguint"`
}

func (m bigUintMessage) WireType() string    { return "test.bigint.unsigned" }
func (m bigUintMessage) WireVersion() uint16 { return 1 }

type bigPosMessage struct {
	Val *big.Int `wire:"1,bigpos"`
}

func (m bigPosMessage) WireType() string    { return "test.bigint.positive" }
func (m bigPosMessage) WireVersion() uint16 { return 1 }

type bigIntValueMessage struct {
	Val big.Int `wire:"1,bigint"`
}

func (m bigIntValueMessage) WireType() string    { return "test.bigint.value" }
func (m bigIntValueMessage) WireVersion() uint16 { return 1 }

type bigIntMaxBytesMessage struct {
	Val *big.Int `wire:"1,bigint,max_bytes=limit"`
}

func (m bigIntMaxBytesMessage) WireType() string    { return "test.bigint.maxbytes" }
func (m bigIntMaxBytesMessage) WireVersion() uint16 { return 1 }

type bigIntMultiFieldMessage struct {
	Signed *big.Int `wire:"1,bigint"`
	Pos    *big.Int `wire:"2,bigpos"`
}

func (m bigIntMultiFieldMessage) WireType() string    { return "test.bigint.multifield" }
func (m bigIntMultiFieldMessage) WireVersion() uint16 { return 1 }

// ---- bigint tests ------------------------------------------------------------

func TestBigIntRoundTripZero(t *testing.T) {
	orig := bigIntSignedMessage{Val: big.NewInt(0)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Sign() != 0 {
		t.Fatalf("zero round-trip: got %v", decoded.Val)
	}
}

func TestBigIntRoundTripPositive(t *testing.T) {
	orig := bigIntSignedMessage{Val: big.NewInt(258)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Cmp(big.NewInt(258)) != 0 {
		t.Fatalf("positive round-trip: got %v", decoded.Val)
	}
}

func TestBigIntRoundTripNegative(t *testing.T) {
	orig := bigIntSignedMessage{Val: big.NewInt(-258)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Cmp(big.NewInt(-258)) != 0 {
		t.Fatalf("negative round-trip: got %v", decoded.Val)
	}
}

func TestBigIntNilPointerIsZero(t *testing.T) {
	orig := bigIntSignedMessage{Val: nil}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Should encode as 0x00.
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val == nil || decoded.Val.Sign() != 0 {
		t.Fatalf("nil pointer round-trip: got %v", decoded.Val)
	}
}

func TestBigIntCanonicalEncoding(t *testing.T) {
	// Zero must encode as [0x00].
	raw0, err := encodeBigIntSigned(big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw0, []byte{0x00}) {
		t.Fatalf("zero encoding: %x", raw0)
	}
	// 258 must encode as [0x00, 0x01, 0x02].
	rawPos, err := encodeBigIntSigned(big.NewInt(258))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawPos, []byte{0x00, 0x01, 0x02}) {
		t.Fatalf("positive encoding: %x", rawPos)
	}
	// -258 must encode as [0x01, 0x01, 0x02].
	rawNeg, err := encodeBigIntSigned(big.NewInt(-258))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawNeg, []byte{0x01, 0x01, 0x02}) {
		t.Fatalf("negative encoding: %x", rawNeg)
	}
}

func TestBigIntCanonicalRemarshal(t *testing.T) {
	orig := bigIntSignedMessage{Val: big.NewInt(12345)}
	raw1, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("bigint marshal is not deterministic")
	}
}

func TestBigIntRejectInvalidSignByte(t *testing.T) {
	// Construct a bigint with invalid sign byte 0x02.
	fields := []Field{
		{Tag: 1, Value: []byte{0x02, 0x01}},
	}
	raw, err := MarshalFields(1, "test.bigint.signed", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for invalid sign byte")
	}
}

func TestBigIntRejectNegativeZero(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte{0x01}}, // sign=negative, empty magnitude
	}
	raw, err := MarshalFields(1, "test.bigint.signed", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for negative zero")
	}
}

func TestBigIntRejectLeadingZeroMagnitude(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte{0x00, 0x00, 0x01}}, // leading zero in magnitude
	}
	raw, err := MarshalFields(1, "test.bigint.signed", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for leading zero in magnitude")
	}
}

func TestBigIntRejectEmptyEncoding(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte{}}, // empty signed integer
	}
	raw, err := MarshalFields(1, "test.bigint.signed", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for empty signed integer encoding")
	}
}

func TestBigIntPointerAutoAlloc(t *testing.T) {
	orig := bigIntSignedMessage{Val: big.NewInt(42)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Unmarshal into nil pointer — codec must auto-allocate.
	var decoded bigIntSignedMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val == nil {
		t.Fatal("pointer field was not auto-allocated")
	}
	if decoded.Val.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("auto-alloc round-trip: got %v", decoded.Val)
	}
}

func TestBigIntValueField(t *testing.T) {
	orig := bigIntValueMessage{}
	orig.Val.SetInt64(-999)
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntValueMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Cmp(big.NewInt(-999)) != 0 {
		t.Fatalf("value field round-trip: got %v", &decoded.Val)
	}
}

// ---- biguint tests -----------------------------------------------------------

func TestBigUintRoundTripZero(t *testing.T) {
	// Zero must encode as empty.
	orig := bigUintMessage{Val: big.NewInt(0)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigUintMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Sign() != 0 {
		t.Fatalf("zero round-trip: got %v", decoded.Val)
	}
}

func TestBigUintRoundTripPositive(t *testing.T) {
	orig := bigUintMessage{Val: big.NewInt(258)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigUintMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Cmp(big.NewInt(258)) != 0 {
		t.Fatalf("positive round-trip: got %v", decoded.Val)
	}
}

func TestBigUintRejectNegative(t *testing.T) {
	orig := bigUintMessage{Val: big.NewInt(-1)}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for negative unsigned integer on marshal")
	}
}

func TestBigUintRejectLeadingZero(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte{0x00, 0x01}},
	}
	raw, err := MarshalFields(1, "test.bigint.unsigned", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigUintMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for leading zero in unsigned integer")
	}
}

func TestBigUintNilPointerIsZero(t *testing.T) {
	orig := bigUintMessage{Val: nil}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigUintMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val == nil || decoded.Val.Sign() != 0 {
		t.Fatalf("nil round-trip for unsigned: got %v", decoded.Val)
	}
}

// ---- bigpos tests ------------------------------------------------------------

func TestBigPosRoundTrip(t *testing.T) {
	orig := bigPosMessage{Val: big.NewInt(258)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigPosMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val.Cmp(big.NewInt(258)) != 0 {
		t.Fatalf("positive round-trip: got %v", decoded.Val)
	}
}

func TestBigPosRejectNil(t *testing.T) {
	orig := bigPosMessage{Val: nil}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for nil positive integer")
	}
}

func TestBigPosRejectZero(t *testing.T) {
	orig := bigPosMessage{Val: big.NewInt(0)}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for zero positive integer")
	}
}

func TestBigPosRejectNegative(t *testing.T) {
	orig := bigPosMessage{Val: big.NewInt(-1)}
	if _, err := Marshal(orig); err == nil {
		t.Fatal("expected error for negative positive integer")
	}
}

func TestBigPosRejectEmpty(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte{}},
	}
	raw, err := MarshalFields(1, "test.bigint.positive", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigPosMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for empty positive integer")
	}
}

func TestBigPosRejectLeadingZero(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte{0x00, 0x01}},
	}
	raw, err := MarshalFields(1, "test.bigint.positive", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigPosMessage
	if err := Unmarshal(raw, &decoded); err == nil {
		t.Fatal("expected error for leading zero in positive integer")
	}
}

func TestBigPosPointerAutoAlloc(t *testing.T) {
	orig := bigPosMessage{Val: big.NewInt(7)}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigPosMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Val == nil {
		t.Fatal("positive pointer was not auto-allocated")
	}
	if decoded.Val.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("auto-alloc round-trip: got %v", decoded.Val)
	}
}

// ---- general big integer tests -----------------------------------------------

func TestBigIntMaxBytesEnforced(t *testing.T) {
	// Encode 258 as bigint -> [0x00, 0x01, 0x02] = 3 bytes.
	// max_bytes=2 should reject.
	fields := []Field{
		{Tag: 1, Value: []byte{0x00, 0x01, 0x02}},
	}
	raw, err := MarshalFields(1, "test.bigint.maxbytes", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntMaxBytesMessage
	err = Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 2}))
	if err == nil {
		t.Fatal("expected max_bytes error for oversized bigint")
	}
	// With adequate limit, should succeed.
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"limit": 10})); err != nil {
		t.Fatalf("unmarshal with adequate limit: %v", err)
	}
}

func TestBigIntErrorWrapping(t *testing.T) {
	// Trigger a decode error with negative zero for bigint.
	fields := []Field{
		{Tag: 1, Value: []byte{0x01}},       // negative zero — invalid
		{Tag: 2, Value: []byte{0x01, 0x02}}, // valid bigpos
	}
	raw, err := MarshalFields(1, "test.bigint.multifield", fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntMultiFieldMessage
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error for negative zero")
	}
	if !strings.Contains(err.Error(), "Signed") || !strings.Contains(err.Error(), "tag 1") {
		t.Fatalf("error should mention field name and tag: %v", err)
	}
}

func TestBigIntFieldOrdering(t *testing.T) {
	orig := bigIntMultiFieldMessage{
		Signed: big.NewInt(-5),
		Pos:    big.NewInt(3),
	}
	raw, err := Marshal(&orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bigIntMultiFieldMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Signed.Cmp(big.NewInt(-5)) != 0 || decoded.Pos.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("field ordering broken: Signed=%v Pos=%v", decoded.Signed, decoded.Pos)
	}
}

func TestBigIntWrongKindOnNonBigIntFails(t *testing.T) {
	type badType struct {
		Val string `wire:"1,bigint"`
	}
	_, err := getSchema(reflect.TypeFor[badType]())
	if err == nil {
		t.Fatal("expected schema error for bigint on string field")
	}
}

func TestBigUintWrongKindOnNonBigIntFails(t *testing.T) {
	type badType struct {
		Val string `wire:"1,biguint"`
	}
	_, err := getSchema(reflect.TypeFor[badType]())
	if err == nil {
		t.Fatal("expected schema error for biguint on string field")
	}
}

func TestBigPosWrongKindOnNonBigIntFails(t *testing.T) {
	type badType struct {
		Val string `wire:"1,bigpos"`
	}
	_, err := getSchema(reflect.TypeFor[badType]())
	if err == nil {
		t.Fatal("expected schema error for bigpos on string field")
	}
}

func FuzzBigIntField(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte{0x01, 0x01})
	f.Add([]byte{0x02, 0x01}) // invalid sign
	f.Add([]byte{0x01})       // negative zero
	f.Add([]byte{0x00, 0x00}) // leading zero
	f.Add([]byte{})           // empty
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, in []byte) {
		fields := []Field{
			{Tag: 1, Value: in},
		}
		raw, err := MarshalFields(1, "test.bigint.signed", fields)
		if err != nil {
			t.Fatal(err)
		}
		var decoded bigIntSignedMessage
		_ = Unmarshal(raw, &decoded)

		// Also fuzz unsigned.
		raw2, err2 := MarshalFields(1, "test.bigint.unsigned", fields)
		if err2 != nil {
			t.Fatal(err2)
		}
		var decoded2 bigUintMessage
		_ = Unmarshal(raw2, &decoded2)

		// Also fuzz positive.
		raw3, err3 := MarshalFields(1, "test.bigint.positive", fields)
		if err3 != nil {
			t.Fatal(err3)
		}
		var decoded3 bigPosMessage
		_ = Unmarshal(raw3, &decoded3)
	})
}

// TestLenMismatchWithArrayLength verifies that len=N is validated against
// the array length at schema parse time for bytes fields.
func TestLenMismatchWithArrayLength(t *testing.T) {
	// len=10 on a [8]byte field should fail.
	type badLenArray struct {
		Val [8]byte `wire:"1,bytes,len=10"`
	}
	_, err := getSchema(reflect.TypeFor[badLenArray]())
	if err == nil {
		t.Fatal("expected schema error for len=10 on [8]byte")
	}

	// len=8 on a [8]byte field should succeed.
	type goodLenArray struct {
		Val [8]byte `wire:"1,bytes,len=8"`
	}
	_, err = getSchema(reflect.TypeFor[goodLenArray]())
	if err != nil {
		t.Fatalf("unexpected error for len=8 on [8]byte: %v", err)
	}
}

func TestInferredKindRoundTrip(t *testing.T) {
	orig := inferredMessage{
		Name:  "test",
		Count: 42,
		Data:  []byte{1, 2, 3},
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded inferredMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != orig.Name || decoded.Count != orig.Count || !bytes.Equal(decoded.Data, orig.Data) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestNamedTypeInferenceRoundTrip(t *testing.T) {
	orig := namedInferredMessage{
		S: "hello",
		N: 7,
	}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded namedInferredMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.S != orig.S || decoded.N != orig.N {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestInferredWithOptionsRoundTrip(t *testing.T) {
	orig := inferredWithOptionsMessage{
		Hash: make([]byte, 32),
		Name: "test-name",
	}
	orig.Hash[0] = 0xff
	orig.Hash[31] = 0x01
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}

	var decoded inferredWithOptionsMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits())); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.Hash, orig.Hash) || decoded.Name != orig.Name {
		t.Fatalf("round-trip mismatch")
	}
}

func TestInferredKindRejectsWrongType(t *testing.T) {
	// Tag-only form for types that cannot be inferred should fail at schema parse time.
	// big.Int is not auto-inferred — must use explicit kind.
	// int64 is not in the inference table.
	type badInferred struct {
		X int64 `wire:"1"`
	}
	_, err := getSchema(reflect.TypeFor[badInferred]())
	if err == nil {
		t.Fatal("expected error for uninferrable type int64")
	}
}

func TestStringMaxBytesRoundTrip(t *testing.T) {
	orig := stringLimitMessage{
		Name: "short",
		Code: "ABCD",
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(testFieldLimits()))
	if err != nil {
		t.Fatal(err)
	}

	var decoded stringLimitMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(testFieldLimits())); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != orig.Name || decoded.Code != orig.Code {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestStringMaxBytesExceededEncode(t *testing.T) {
	ls := FieldLimits{"name": 5}
	orig := stringLimitMessage{
		Name: "too-long-name",
		Code: "ABCD",
	}
	_, err := Marshal(orig, WithFieldLimitsForMarshal(ls))
	if err == nil {
		t.Fatal("expected error for string exceeding max_bytes during encode")
	}
}

func TestStringMaxBytesExceededDecode(t *testing.T) {
	// Build a wire message with an over-long string value by using a field-level API.
	fields := []Field{
		{Tag: 1, Value: []byte("too-long-name")},
		{Tag: 2, Value: []byte("ABCD")},
	}
	raw, err := MarshalFields(1, "test.stringlimit", fields)
	if err != nil {
		t.Fatal(err)
	}

	ls := FieldLimits{"name": 5}
	var decoded stringLimitMessage
	err = Unmarshal(raw, &decoded, WithFrameLimits(FrameLimits{
		MaxTotalBytes: 1 << 20,
		MaxFields:     256,
		MaxFieldBytes: 1 << 20,
	}), WithFieldLimits(ls))
	if err == nil {
		t.Fatal("expected error for string exceeding max_bytes during decode")
	}
}

func TestStringLenEncode(t *testing.T) {
	orig := stringLimitMessage{
		Name: "ok",
		Code: "ABC", // too short for len=4
	}
	_, err := Marshal(orig)
	if err == nil {
		t.Fatal("expected error for string not matching len=4 during encode")
	}
}

func TestStringLenDecode(t *testing.T) {
	fields := []Field{
		{Tag: 1, Value: []byte("ok")},
		{Tag: 2, Value: []byte("AB")}, // too short for len=4
	}
	raw, err := MarshalFields(1, "test.stringlimit", fields)
	if err != nil {
		t.Fatal(err)
	}

	var decoded stringLimitMessage
	err = Unmarshal(raw, &decoded, WithFrameLimits(FrameLimits{
		MaxTotalBytes: 1 << 20,
		MaxFields:     256,
		MaxFieldBytes: 1 << 20,
	}))
	if err == nil {
		t.Fatal("expected error for string not matching len=4 during decode")
	}
}

func TestStringLimitInferredRoundTrip(t *testing.T) {
	orig := stringLimitInferredMessage{
		Name: "test",
	}
	raw, err := Marshal(orig, WithFieldLimitsForMarshal(FieldLimits{"name": 10}))
	if err != nil {
		t.Fatal(err)
	}

	var decoded stringLimitInferredMessage
	if err := Unmarshal(raw, &decoded, WithFieldLimits(FieldLimits{"name": 10})); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != orig.Name {
		t.Fatalf("round-trip mismatch: got %q, want %q", decoded.Name, orig.Name)
	}
}
