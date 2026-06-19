package wire

import "math/big"

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
		"limit": 1000,
	}
}

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

type intU32ListMessage struct {
	IDs []int `wire:"1,u32list"`
}

func (m intU32ListMessage) WireType() string    { return "test.intu32list" }
func (m intU32ListMessage) WireVersion() uint16 { return 1 }

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

type nestedLimitInnerMessage struct {
	Payload []byte `wire:"1,bytes,max_bytes=field"`
}

func (m nestedLimitInnerMessage) WireType() string    { return "test.nestedlimit.inner" }
func (m nestedLimitInnerMessage) WireVersion() uint16 { return 1 }

type nestedLimitMessage struct {
	Inner nestedLimitInnerMessage `wire:"1,nested"`
}

func (m nestedLimitMessage) WireType() string    { return "test.nestedlimit" }
func (m nestedLimitMessage) WireVersion() uint16 { return 1 }

type nestedOuterLimitInnerMessage struct {
	Payload []byte `wire:"1,bytes"`
}

func (m nestedOuterLimitInnerMessage) WireType() string    { return "test.nestedouterlimit.inner" }
func (m nestedOuterLimitInnerMessage) WireVersion() uint16 { return 1 }

type nestedOuterLimitMessage struct {
	Inner nestedOuterLimitInnerMessage `wire:"1,nested,max_bytes=field"`
}

func (m nestedOuterLimitMessage) WireType() string    { return "test.nestedouterlimit" }
func (m nestedOuterLimitMessage) WireVersion() uint16 { return 1 }

type nestedPointerMessage struct {
	Inner *nestedOuterLimitInnerMessage `wire:"1,nested,max_bytes=field"`
}

func (m nestedPointerMessage) WireType() string    { return "test.nestedpointer" }
func (m nestedPointerMessage) WireVersion() uint16 { return 1 }

type optionalNestedPointerMessage struct {
	Inner *nestedOuterLimitInnerMessage `wire:"1,nested,max_bytes=field,optional"`
	Tag   uint32                        `wire:"2,u32"`
}

func (m optionalNestedPointerMessage) WireType() string    { return "test.optionalnestedpointer" }
func (m optionalNestedPointerMessage) WireVersion() uint16 { return 1 }

type nestedHookInnerMessage struct {
	AfterCalled bool
	Value       uint16 `wire:"1,u16"`
}

func (m nestedHookInnerMessage) WireType() string    { return "test.nestedhook.inner" }
func (m nestedHookInnerMessage) WireVersion() uint16 { return 1 }
func (m *nestedHookInnerMessage) AfterUnmarshalWire() error {
	m.AfterCalled = true
	return nil
}
func (m nestedHookInnerMessage) Validate() error {
	if m.Value == 0 {
		return errSentinel
	}
	return nil
}

type nestedHookMessage struct {
	Inner nestedHookInnerMessage `wire:"1,nested"`
}

func (m nestedHookMessage) WireType() string    { return "test.nestedhook" }
func (m nestedHookMessage) WireVersion() uint16 { return 1 }

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

// customNoUnmarshal implements MarshalWireValue but not UnmarshalWireValue.
type customNoUnmarshal struct {
	raw []byte
}

func (c customNoUnmarshal) MarshalWireValue() ([]byte, error) {
	return c.raw, nil
}

// customNoMarshal implements UnmarshalWireValue but not MarshalWireValue.
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

type customCountedList struct {
	items [][]byte
}

func (c customCountedList) MarshalWireValue() ([]byte, error) {
	return EncodeBytesList(c.items), nil
}

func (c *customCountedList) UnmarshalWireValue(in []byte) error {
	items, err := DecodeBytesList(in)
	if err != nil {
		return err
	}
	c.items = make([][]byte, len(items))
	for i, item := range items {
		c.items[i] = append([]byte(nil), item...)
	}
	return nil
}

type customMaxItemsMessage struct {
	Data customCountedList `wire:"1,custom,max_items=items"`
}

func (m customMaxItemsMessage) WireType() string    { return "test.custom.maxitems" }
func (m customMaxItemsMessage) WireVersion() uint16 { return 1 }

type optionalCustomMaxItemsMessage struct {
	Data *customCountedList `wire:"1,custom,optional,max_items=items"`
}

func (m optionalCustomMaxItemsMessage) WireType() string {
	return "test.custom.maxitems.optional"
}

func (m optionalCustomMaxItemsMessage) WireVersion() uint16 { return 1 }

type panicOnUnmarshalCustomList struct{}

func (panicOnUnmarshalCustomList) MarshalWireValue() ([]byte, error) {
	return Uint32(0), nil
}

func (*panicOnUnmarshalCustomList) UnmarshalWireValue([]byte) error {
	panic("custom unmarshal should not be called")
}

type panicCustomMaxItemsMessage struct {
	Data panicOnUnmarshalCustomList `wire:"1,custom,max_items=items"`
}

func (m panicCustomMaxItemsMessage) WireType() string {
	return "test.custom.maxitems.panic"
}

func (m panicCustomMaxItemsMessage) WireVersion() uint16 { return 1 }

type rawCustomMaxItemsMessage struct {
	Data customBytes `wire:"1,custom,max_items=items"`
}

func (m rawCustomMaxItemsMessage) WireType() string {
	return "test.custom.maxitems.raw"
}

func (m rawCustomMaxItemsMessage) WireVersion() uint16 { return 1 }

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

// bigPosMaxBitsMessage tests max_bits enforcement on bigpos fields.
type bigPosMaxBitsMessage struct {
	Val *big.Int `wire:"1,bigpos,max_bits=limit"`
}

func (m bigPosMaxBitsMessage) WireType() string    { return "test.bigpos.maxbits" }
func (m bigPosMaxBitsMessage) WireVersion() uint16 { return 1 }

// bytesMaxBitsMessage tests max_bits enforcement on bytes fields.
type bytesMaxBitsMessage struct {
	Data []byte `wire:"1,bytes,max_bits=limit"`
}

func (m bytesMaxBitsMessage) WireType() string    { return "test.bytes.maxbits" }
func (m bytesMaxBitsMessage) WireVersion() uint16 { return 1 }

var errSentinel = &testError{"sentinel"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
