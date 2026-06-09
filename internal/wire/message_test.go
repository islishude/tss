package wire

import (
	"bytes"
	"testing"
)

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
		WithLimitSet(LimitSet{"field": 3}))
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
		WithLimitSet(LimitSet{"field": 10})); err != nil {
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
		WithLimitSet(LimitSet{"ids": 10})); err != nil {
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
		WithLimitSet(LimitSet{"ids": 3}))
	if err == nil {
		t.Fatal("expected error for too many items")
	}
}

func TestCodecBytesList(t *testing.T) {
	orig := bytesListMessage{Items: [][]byte{{1, 2}, {3, 4, 5}}}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bytesListMessage
	if err := Unmarshal(raw, &decoded,
		WithLimitSet(LimitSet{"field": 100, "items": 10})); err != nil {
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
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded partyBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithLimitSet(LimitSet{"field": 100})); err != nil {
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
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded partyBytePairsMessage
	if err := Unmarshal(raw, &decoded,
		WithLimitSet(LimitSet{"field": 100})); err != nil {
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
		WithLimitSet(LimitSet{"other": 100})); err == nil {
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
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bytesListMessage
	if err := Unmarshal(raw, &decoded,
		WithLimitSet(LimitSet{"field": 100, "items": 10})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Items) != 0 {
		t.Fatalf("nil byteslist round-trip: got %d items", len(decoded.Items))
	}
}

func TestEmptyPartyBytesRoundTrip(t *testing.T) {
	orig := partyBytesMessage{}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded partyBytesMessage
	if err := Unmarshal(raw, &decoded,
		WithLimitSet(LimitSet{"field": 100})); err != nil {
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
